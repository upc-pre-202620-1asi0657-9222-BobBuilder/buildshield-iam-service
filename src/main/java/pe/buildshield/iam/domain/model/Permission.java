package pe.buildshield.iam.domain.model;

/**
 * Permisos de un rol (agregado Permission del C4, pág. 27 de la v4). Salen de las responsabilidades de cada
 * persona en el C4 de contenedores (pág. 21). No tienen tabla: se derivan del rol. La web los usa para mostrar
 * u ocultar acciones; cada servicio sigue validando el rol con {@code @PreAuthorize}.
 */
public enum Permission {

    /** Administrador: gestiona usuarios y sus roles. */
    MANAGE_USERS,
    /** Administrador: gestiona obras y almacenes. */
    MANAGE_LOCATIONS,
    /** Administrador: gestiona la suscripción de la constructora. */
    MANAGE_SUBSCRIPTION,
    /** Encargado de almacén: atiende pedidos. */
    ATTEND_ORDERS,
    /** Encargado de almacén: registra despachos, pesaje y evidencias. */
    REGISTER_DISPATCHES,
    /** Encargado de obra: pide material. */
    REQUEST_MATERIAL,
    /** Encargado de obra: recibe despachos. */
    RECEIVE_DISPATCHES,
    /** Encargado de obra: registra discrepancias. */
    REGISTER_DISCREPANCIES
}
