package in.gov.ntro.sih.ms.repo;

import in.gov.ntro.sih.ms.domain.Asset;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AssetRepository extends JpaRepository<Asset, Long> {
    List<Asset> findByCaptureIdOrderByExposureScoreDesc(Long captureId);
}
