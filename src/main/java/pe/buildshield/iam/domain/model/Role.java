package pe.buildshield.iam.domain.model;

import pe.buildshield.iam.shared.error.ErrorDetail;
import pe.buildshield.iam.shared.error.ValidationException;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/** Roles de un usuario dentro de su organización. */
public enum Role {

    ADMINISTRATOR("administrador", EnumSet.of(Permission.MANAGE_USERS, Permission.MANAGE_LOCATIONS,
            Permission.MANAGE_SUBSCRIPTION)),
    WAREHOUSE_MANAGER("encargado de almacén", EnumSet.of(Permission.ATTEND_ORDERS, Permission.REGISTER_DISPATCHES)),
    SITE_MANAGER("encargado de obra", EnumSet.of(Permission.REQUEST_MATERIAL, Permission.RECEIVE_DISPATCHES,
            Permission.REGISTER_DISCREPANCIES));

    private final String displayName;
    private final Set<Permission> permissions;

    Role(String displayName, Set<Permission> permissions) {
        this.displayName = displayName;
        this.permissions = permissions;
    }

    /** Permisos del rol, en el orden del enum. */
    public Set<Permission> permissions() {
        return EnumSet.copyOf(permissions);
    }

    public String displayName() {
        return displayName;
    }

    /** Acepta el nombre del rol ({@code WAREHOUSE_MANAGER}). */
    public static Role parse(String value) {
        return Arrays.stream(values())
                .filter(role -> role.name().equalsIgnoreCase(value == null ? "" : value.trim()))
                .findFirst()
                .orElseThrow(() -> new ValidationException("INVALID_ROLE",
                        "El rol debe ser ADMINISTRATOR, WAREHOUSE_MANAGER o SITE_MANAGER",
                        List.of(new ErrorDetail("role", "rol desconocido: " + value))));
    }
}
