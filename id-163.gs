/**
 * Estrategia de Auditoría para Gestor de Contraseñas de Chrome (ID-163).
 * Evalúa si la organización permite que los usuarios guarden contraseñas en el navegador Chrome.
 * * ID Evaluado: ID-163
 * Configuración Evaluada: Password manager
 * Filtro de Esquema / Búsqueda: chrome.users.PasswordManager
 * Variable de Configuración Real API: passwordManagerEnabled (camelCase)
 */
class ChromePasswordManagerStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-163",
        valueKey: "valorPrincipal",
        noteKey: "comentario163",
        riskKey: "riesgo163",
        scoreKey: "score163"
      }
    ];

    super("Chrome Password Manager Settings Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Gestión de navegadores";
  }

  /**
   * Evalúa la política 'chrome.users.PasswordManager' en la raíz del dominio.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-163 (PASSWORD MANAGER) ==========");

    // 1. Obtener Token DWD
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[ID-163] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[ID-163 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
      return this._buildErrorResponse(`Fallo al generar token DWD: ${e.message}`);
    }

    // 2. Mapeo Robusto de la OU raíz (Para evitar Error 404 de la API)
    let rootOuId = "";
    try {
      const response = AdminDirectory.Orgunits.list(this.customerId, { type: "all" });
      const orgUnits = response.organizationUnits || [];
      
      // A: Buscar hija directa de la raíz "/"
      const childOfRoot = orgUnits.find(ou => ou.parentOrgUnitPath === "/");
      if (childOfRoot && childOfRoot.parentOrgUnitId) {
        rootOuId = childOfRoot.parentOrgUnitId.replace(/^id:/, "");
        Logger.log(`[ID-163] Raíz resuelta por hija directa: ${rootOuId}`);
      } 
      // B: Buscar cualquier OU que tenga un padre
      else if (orgUnits.length > 0) {
        const anyOuWithParent = orgUnits.find(ou => ou.parentOrgUnitId);
        if (anyOuWithParent) {
          rootOuId = anyOuWithParent.parentOrgUnitId.replace(/^id:/, "");
          Logger.log(`[ID-163] Raíz resuelta por OU genérica: ${rootOuId}`);
        }
      }
    } catch (e) {
      Logger.log(`[ID-163 - WARN] No se pudo mapear la raíz vía AdminDirectory: ${e.message}`);
    }

    // C: Usar el customerId solo si es un formato canónico (ej: 03ph...) y no "my_customer"
    if (!rootOuId && this.customerId && this.customerId !== "my_customer") {
      rootOuId = this.customerId;
    }

    // Bloqueo preventivo de 404 (Chrome Policy API rechaza el literal 'my_customer' en policies:resolve)
    if (!rootOuId || rootOuId === "my_customer") {
      Logger.log("[ID-163 - ERROR CRÍTICO] No se pudo obtener el ID real de la OU.");
      return this._buildErrorResponse("No se pudo resolver el ID de la OU raíz (Se bloqueó la petición para evitar Error 404). Verifica AdminDirectory.");
    }

    const targetResource = `orgunits/${rootOuId}`;
    Logger.log(`[ID-163] Target Resource definitivo para la API: ${targetResource}`);

    let passwordManagerEnabled = null;
    let anyFound = false;
    let schemaNotFound = false;

    // 3. Preparar la llamada a la Chrome Policy API con el esquema corregido
    const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
    const payload = {
      policyTargetKey: {
        targetResource: targetResource
      },
      policySchemaFilter: "chrome.users.PasswordManager", // ESQUEMA CORREGIDO
      pageSize: 100
    };

    const options = {
      method: "post",
      headers: {
        ...dwdHeader,
        "Content-Type": "application/json",
        "Cache-Control": "no-cache"
      },
      payload: JSON.stringify(payload),
      muteHttpExceptions: true
    };

    Logger.log("[ID-163] Solicitando política chrome.users.PasswordManager...");
    try {
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      Logger.log(`[ID-163 - DETALLE API] HTTP Code: ${code}`);
      Logger.log(`[ID-163 - DETALLE API] RAW JSON: ${text}`);

      if (code === 200) {
        const json = JSON.parse(text);
        const resolvedPolicies = json.resolvedPolicies || [];
        
        if (resolvedPolicies.length > 0) {
          anyFound = true;
          resolvedPolicies.forEach((policy) => {
            const val = policy.value && policy.value.value;
            // Se sigue validando con la variable interna camelCase
            if (val && val.passwordManagerEnabled !== undefined) {
              passwordManagerEnabled = val.passwordManagerEnabled;
              Logger.log(`[ID-163 - PARSEO] Encontrada variable 'passwordManagerEnabled'. Valor: ${passwordManagerEnabled}`);
            }
          });
        } else {
          Logger.log("[ID-163 - INFO] La API no devolvió políticas activas para este esquema. Asumiendo valor por defecto de Google.");
        }
      } else if (code === 404) {
        schemaNotFound = true;
        Logger.log(`[ID-163 - WARN] Esquema no encontrado en la API (HTTP 404). Posible deprecación o namespace incorrecto.`);
      } else {
        Logger.log(`[ID-163 - ERROR] Petición fallida a la API con HTTP ${code}`);
      }
    } catch (e) {
      Logger.log(`[ID-163 - ERROR EXCEPCIÓN] Fallo de red: ${e.message}`);
    }

    // 4. Lógica de Riesgos y Construcción de la Respuesta
    let riesgo163, comentario163, valorPrincipal;

    if (schemaNotFound) {
      riesgo163 = "Medio";
      valorPrincipal = "No Disponible vía API";
      comentario163 = "El esquema de política no fue encontrado en la Chrome Policy API (HTTP 404). Es posible que la política haya sido deprecada, renombrada, o pertenezca a un nivel jerárquico diferente.";
    } else if (!anyFound || passwordManagerEnabled === null || passwordManagerEnabled === true) {
      riesgo163 = "Alto";
      valorPrincipal = (passwordManagerEnabled === true) ? "Habilitado" : "Habilitado por defecto";
      comentario163 = "El gestor de contraseñas de Chrome está permitido. Esto incrementa el riesgo de que las credenciales corporativas se almacenen localmente en el navegador, pudiendo ser comprometidas si un atacante obtiene acceso al perfil de usuario o al dispositivo.";
    } else {
      // passwordManagerEnabled === false
      riesgo163 = "Bajo";
      valorPrincipal = "Deshabilitado";
      comentario163 = "El gestor de contraseñas de Chrome está desactivado por política. Esto es una excelente práctica para forzar el uso de herramientas de gestión de credenciales autorizadas y evitar que contraseñas sensibles queden cacheadas en el navegador.";
    }

    Logger.log(`[ID-163] Diagnóstico Terminado. Valor Detectado: ${passwordManagerEnabled} | Riesgo Asignado: ${riesgo163}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-163 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario163: comentario163,
      riesgo163: riesgo163,
      score163: this.calcularScoreDeRiesgo(riesgo163)
    };
  }

  /**
   * Mapeo de puntajes.
   */
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  /**
   * Manejador de fallos de API.
   */
  _buildErrorResponse(msg) {
    Logger.log(`[ID-163] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario163: `Ocurrió un error inesperado al procesar la API: ${msg}`,
      riesgo163: "Medio",
      score163: 2
    };
  }
}