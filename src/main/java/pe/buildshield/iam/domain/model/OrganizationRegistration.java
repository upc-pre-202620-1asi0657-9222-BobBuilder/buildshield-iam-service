package pe.buildshield.iam.domain.model;

import pe.buildshield.iam.shared.error.ErrorDetail;
import pe.buildshield.iam.shared.error.ValidationException;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Alta de una empresa cliente (US01): su identificador, que es el {@code organization_id} de todos sus
 * datos en todos los servicios, su RUC y su razón social. iam la valida y la publica con el evento
 * {@code OrganizationRegistered}; Organización y Configuración guarda la organización al consumirlo.
 */
public record OrganizationRegistration(UUID organizationId, Ruc ruc, String legalName) {

    static final int MAX_LEGAL_NAME = 200;

    public OrganizationRegistration {
        Objects.requireNonNull(organizationId, "organizationId");
        Objects.requireNonNull(ruc, "ruc");
        if (legalName == null || legalName.isBlank() || legalName.trim().length() > MAX_LEGAL_NAME) {
            throw new ValidationException("INVALID_LEGAL_NAME", "La razón social es obligatoria (máximo 200 caracteres)",
                    List.of(new ErrorDetail("legalName", "obligatoria, máximo 200 caracteres")));
        }
        legalName = legalName.trim();
    }

    public static OrganizationRegistration of(UUID organizationId, String ruc, String legalName) {
        return new OrganizationRegistration(organizationId, new Ruc(ruc), legalName);
    }
}
