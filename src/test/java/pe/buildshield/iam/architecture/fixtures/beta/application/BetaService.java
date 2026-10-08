package pe.buildshield.iam.architecture.fixtures.beta.application;

import pe.buildshield.iam.architecture.fixtures.alpha.AlphaFacade;
import pe.buildshield.iam.architecture.fixtures.alpha.infrastructure.AlphaRepository;

/** Clase de ejemplo: usa la fachada de alpha (permitido) y su repositorio (violación). */
public class BetaService {

    private final AlphaFacade facade = new AlphaFacade();
    private final AlphaRepository repository = new AlphaRepository();

    public String run() {
        return facade.find() + repository.find();
    }
}
