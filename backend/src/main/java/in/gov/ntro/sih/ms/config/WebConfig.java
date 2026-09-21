package in.gov.ntro.sih.ms.config;

import java.io.IOException;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.PathResourceResolver;

/**
 * CORS for the Vite dev server, and SPA routing so a deep link such as
 * /report/3/sessions/0 reaches index.html instead of a 404.
 *
 * <p><b>Why this is a resource resolver and not a view controller.</b> The
 * obvious way to do SPA routing is to forward every dotless path to
 * index.html:
 *
 * <pre>
 * registry.addViewController("/{path:^(?!api|actuator|assets)[^.]*}/**")
 *         .setViewName("forward:/index.html");
 * </pre>
 *
 * <p>That is what this class used to do, and it is wrong in a way that is very
 * hard to see. View-controller mappings sit at order 1; static resource
 * handling sits at {@code Integer.MAX_VALUE - 1}. So the forward wins against
 * files that really exist, and any URL whose <em>first</em> segment has no dot
 * is swallowed whole — including {@code /samples/smtp.json}, the bundled engine
 * reports the dashboard loads when no capture has been uploaded. The browser
 * asked for JSON, got <b>HTTP 200 and index.html</b>, and reported
 * {@code Unexpected token '<', "<!doctype "... is not valid JSON}. A 200 also
 * defeats every {@code res.ok} check on the client, so the front end could not
 * tell a missing file from a working one.
 *
 * <p>Resolving the resource first fixes both halves. A file that exists is
 * served as itself. A path that looks like a file and is missing gets an honest
 * 404, so client-side error handling means something again. Only extensionless
 * paths — actual application routes — fall through to index.html.
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins("http://localhost:5173", "http://127.0.0.1:5173")
                .allowedMethods("GET", "POST", "DELETE", "OPTIONS")
                .allowedHeaders("*");
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/**")
                .addResourceLocations("classpath:/static/")
                .resourceChain(true)
                .addResolver(new PathResourceResolver() {
                    @Override
                    protected Resource getResource(String resourcePath, Resource location)
                            throws IOException {
                        Resource requested = location.createRelative(resourcePath);
                        if (requested.exists() && requested.isReadable()) {
                            return requested;
                        }
                        // The REST API is mapped by controllers and never reaches
                        // here, but be explicit rather than rely on ordering.
                        if (resourcePath.startsWith("api/") || resourcePath.startsWith("actuator/")) {
                            return null;
                        }
                        // Something with an extension is a file request. If it is
                        // not on disk, say so — handing back index.html with a 200
                        // is how a missing sample report became a JSON parse error.
                        if (hasExtension(resourcePath)) {
                            return null;
                        }
                        Resource index = new ClassPathResource("/static/index.html");
                        return index.exists() ? index : null;
                    }
                });
    }

    /** True when the last path segment carries a file extension. */
    private static boolean hasExtension(String resourcePath) {
        int lastSlash = resourcePath.lastIndexOf('/');
        String last = lastSlash < 0 ? resourcePath : resourcePath.substring(lastSlash + 1);
        return last.lastIndexOf('.') > 0;
    }
}
