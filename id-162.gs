/**
 * Estrategia de Auditoría para Política de instalación de Endpoint Verification (ID-162).
 * Evalúa si la extensión oficial de EV está forzada a través de Chrome Policy API.
 * * Filtro de Esquema / Búsqueda: chrome.users.ExtensionInstallForcelist
 * Variable de Configuración Real API: extensionInstallForcelist
 */
class ChromeEndpointVerificationStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-162",
        valueKey: "valorPrincipal",
        noteKey: "comentario162",
        riskKey: "riesgo162",
        scoreKey: "score162"
      }
    ];

    super("Endpoint Verification Install Policy Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Gestión de navegadores";
  }

  /**
   * Evalúa la política 'chrome.users.ExtensionInstallForcelist' en la raíz del dominio.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-162 (ENDPOINT VERIFICATION) ==========");

    // 1. Autenticación DWD
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[ID-162] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[ID-162 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
      return this._buildErrorResponse(`Fallo al generar token DWD: ${e.message}`);
    }

    // 2. Mapeo de la OU raíz (CORREGIDO PARA EVITAR ERROR 404)
    let rootOuId = "";
    try {
      const response = AdminDirectory.Orgunits.list(this.customerId, { type: "all" });
      const orgUnits = response.organizationUnits || [];
      
      // Estrategia A: Buscar hija directa de la raíz "/"
      const childOfRoot = orgUnits.find(ou => ou.parentOrgUnitPath === "/");
      if (childOfRoot && childOfRoot.parentOrgUnitId) {
        rootOuId = childOfRoot.parentOrgUnitId.replace(/^id:/, "");
        Logger.log(`[ID-162] Raíz resuelta por hija directa: ${rootOuId}`);
      } 
      // Estrategia B: Buscar cualquier OU que tenga un padre (si no hay hijas directas explícitas)
      else if (orgUnits.length > 0) {
        const anyOuWithParent = orgUnits.find(ou => ou.parentOrgUnitId);
        if (anyOuWithParent) {
          rootOuId = anyOuWithParent.parentOrgUnitId.replace(/^id:/, "");
          Logger.log(`[ID-162] Raíz resuelta por OU genérica: ${rootOuId}`);
        }
      }
    } catch (e) {
      Logger.log(`[ID-162 - WARN] No se pudo mapear la raíz vía AdminDirectory: ${e.message}`);
    }

    // Estrategia C: Usar el customerId SI Y SOLO SI es un ID canónico real (ej: 03ph...) y no "my_customer"
    if (!rootOuId && this.customerId && this.customerId !== "my_customer") {
      rootOuId = this.customerId;
    }

    // Si fallan todas las estrategias y queda "my_customer", abortamos para evitar el 404
    if (!rootOuId || rootOuId === "my_customer") {
      Logger.log("[ID-162 - ERROR CRÍTICO] No se pudo obtener el ID real de la OU. 'my_customer' causará un Error 404.");
      return this._buildErrorResponse("No se pudo resolver el ID de la OU raíz (Se bloqueó la petición para evitar Error 404). Verifica AdminDirectory.");
    }

    const targetResource = `orgunits/${rootOuId}`;
    Logger.log(`[ID-162] Target Resource definitivo para la API: ${targetResource}`);

    // Variables base
    let forceList = [];
    let isEVForced = false;
    let schemaNotFound = false;
    // ID oficial de la extensión de Endpoint Verification
    const evExtensionId = "callobklhcbilhphinckomhgkigmfocg"; 

    // 3. Consulta a la API
    const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
    const payload = {
      policyTargetKey: {
        targetResource: targetResource
      },
      policySchemaFilter: "chrome.users.ExtensionInstallForcelist",
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

    Logger.log("[ID-162] Solicitando política de forzado de extensiones (ExtensionInstallForcelist)...");
    try {
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      Logger.log(`[ID-162 - DETALLE API] HTTP Code: ${code}`);
      Logger.log(`[ID-162 - DETALLE API] RAW JSON: ${text}`);

      if (code === 200) {
        const json = JSON.parse(text);
        const resolvedPolicies = json.resolvedPolicies || [];
        
        if (resolvedPolicies.length > 0) {
          resolvedPolicies.forEach((policy, index) => {
            const val = policy.value && policy.value.value;
            // Validamos que exista la lista de extensiones
            if (val && val.extensionInstallForcelist) {
              forceList = forceList.concat(val.extensionInstallForcelist);
              Logger.log(`[ID-162 - PARSEO] Se encontró una lista (parcial o total) con ${val.extensionInstallForcelist.length} extensiones.`);
            }
          });

          // Los IDs forzados usualmente se devuelven en un string delimitado por ";" (Ej. ID_EXTENSION;URL_UPDATE)
          isEVForced = forceList.some(item => item.includes(evExtensionId));
          
        } else {
          Logger.log("[ID-162 - INFO] La API respondió 200, pero no devolvió políticas activas para el esquema (Lista vacía o hereda nulo).");
        }
      } else if (code === 404) {
        schemaNotFound = true;
        Logger.log(`[ID-162 - WARN] Esquema 'chrome.users.ExtensionInstallForcelist' no encontrado en la API (HTTP 404). Posible deprecación o namespace incorrecto.`);
      } else {
        Logger.log(`[ID-162 - ERROR] Petición fallida a la API con HTTP ${code}`);
      }
    } catch (e) {
      Logger.log(`[ID-162 - ERROR EXCEPCIÓN] Fallo de red: ${e.message}`);
    }

    // 4. Lógica de Riesgos y Puntuación
    let riesgo162, comentario162, valorPrincipal;

    if (schemaNotFound) {
      riesgo162 = "Medio";
      valorPrincipal = "No Disponible vía API";
      comentario162 = "El esquema de política no fue encontrado en la Chrome Policy API (HTTP 404). Es posible que la política haya sido deprecada, renombrada, o pertenezca a un nivel jerárquico diferente.";
    } else if (isEVForced) {
      riesgo162 = "Bajo";
      valorPrincipal = "Forzado";
      comentario162 = `La extensión de Endpoint Verification (${evExtensionId}) está configurada correctamente en la lista de instalación forzada ('extensionInstallForcelist'). Esto asegura la recopilación obligatoria de la postura del dispositivo para utilizar Context-Aware Access.`;
    } else {
      riesgo162 = "Alto";
      valorPrincipal = "No Configurado (0)";
      comentario162 = `No se detectó la instalación forzada de Endpoint Verification en la raíz. (Extensiones forzadas en total: ${forceList.length}). Esto representa un riesgo, ya que los informes de seguridad y los bloqueos por Context-Aware Access no operarán de forma segura en dispositivos no gestionados.`;
    }

    Logger.log(`[ID-162] Diagnóstico Terminado. ¿EV detectado?: ${isEVForced} | Riesgo: ${riesgo162}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-162 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario162: comentario162,
      riesgo162: riesgo162,
      score162: this.calcularScoreDeRiesgo(riesgo162)
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
    Logger.log(`[ID-162] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario162: `Ocurrió un error inesperado al procesar la API: ${msg}`,
      riesgo162: "Medio",
      score162: 2
    };
  }
}