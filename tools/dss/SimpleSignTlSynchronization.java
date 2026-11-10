package eu.europa.esig.dss.web.config;

import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

/**
 * Makes the DSS demo's trusted-list job keep only lists whose signature verifies, as ETSI TS 119 615 asks
 * (and as SimpleSign's TrustedList reader does). The demo leaves the job's default, AcceptAllStrategy, which
 * keeps the trust anchors of a list whose signature fails and only reports it in the qualification checks.
 * Expired lists are kept: the TLNotExpired constraint of the validation policy judges them.
 *
 * Compiled into the image by tools/dss/Dockerfile; DSS_ACCEPT_INVALID_TRUSTED_LISTS=true restores the demo's
 * behaviour. Found by the demo's component scan (package eu.europa.esig.dss.web).
 */
@Component
public class SimpleSignTlSynchronization implements BeanPostProcessor {

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) {
        if (bean instanceof TLValidationJob job && !"true".equalsIgnoreCase(System.getenv("DSS_ACCEPT_INVALID_TRUSTED_LISTS"))) {
            ExpirationAndSignatureCheckStrategy strategy = new ExpirationAndSignatureCheckStrategy();
            strategy.setAcceptExpiredTrustedList(true);
            strategy.setAcceptInvalidTrustedList(false);
            strategy.setAcceptExpiredListOfTrustedLists(true);
            strategy.setAcceptInvalidListOfTrustedLists(false);
            job.setSynchronizationStrategy(strategy);
            System.out.println("[dss] trusted lists: only lists whose signature verifies are used (TS 119 615)");
        }

        return bean;
    }
}
