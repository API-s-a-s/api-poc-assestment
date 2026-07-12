/**
 * Estrategia de Auditoría para la Integridad del Código del Renderizador (ID-165).
 * Evalúa si la organización fuerza la verificación de firmas en el código que se carga
 * en los procesos de renderizado de Chrome para prevenir inyecciones de procesos.
 * * ID Evaluado: ID-165
 * Configuración Evaluada: Habilitar la integridad del código del renderizador (habilitado por defecto)
 * Filtro de Esquema / Búsqueda: chrome.users.RendererCodeIntegrity
 * Variable de Configuración Real API: rendererCodeIntegrityEnabled (camelCase)
 */
class ChromeRendererCodeIntegrityStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-165",
        valueKey: "valorPrincipal",
        noteKey: "comentario165",
        riskKey: "riesgo165",
        scoreKey: "score165"
      }
    ];

    super("Chrome Renderer Code Integrity Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Gestión de navegadores";
  }

  /**
   * Evalúa la política 'chrome.users.RendererCodeIntegrity' en la raíz del dominio.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-165 (RENDERER CODE INTEGRITY) ==========");

    // 1. Obtener Token DWD
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[ID-165] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[ID-165 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
      return this._buildErrorResponse(`Fallo al generar token DWD: ${e.message}`);
    }

    // 2. Mapeo Robusto de la OU raíz (Para evitar Error 404)
    let rootOuId = "";
    try {
      const response = AdminDirectory.Orgunits.list(this.customerId, { type: "all" });
      const orgUnits = response.organizationUnits || [];
      
      const childOfRoot = orgUnits.find(ou => ou.parentOrgUnitPath === "/");
      if (childOfRoot && childOfRoot.parentOrgUnitId) {
        rootOuId = childOfRoot.parentOrgUnitId.replace(/^id:/, "");
        Logger.log(`[ID-165] Raíz resuelta por hija directa: ${rootOuId}`);
      } else if (orgUnits.length > 0) {
        const anyOuWithParent = orgUnits.find(ou => ou.parentOrgUnitId);
        if (anyOuWithParent) {
          rootOuId = anyOuWithParent.parentOrgUnitId.replace(/^id:/, "");
          Logger.log(`[ID-165] Raíz resuelta por OU genérica: ${rootOuId}`);
        }
      }
    } catch (e) {
      Logger.log(`[ID-165 - WARN] No se pudo mapear la raíz vía AdminDirectory: ${e.message}`);
    }

    if (!rootOuId && this.customerId && this.customerId !== "my_customer") {
      rootOuId = this.customerId;
    }

    // Bloqueo preventivo de 404
    if (!rootOuId || rootOuId === "my_customer") {
      Logger.log("[ID-165 - ERROR CRÍTICO] No se pudo obtener el ID real de la OU.");
      return this._buildErrorResponse("No se pudo resolver el ID de la OU raíz (Se bloqueó la petición para evitar Error 404).");
    }

    const targetResource = `orgunits/${rootOuId}`;
    Logger.log(`[ID-165] Target Resource definitivo para la API: ${targetResource}`);

    let rendererCodeIntegrityEnabled = null;
    let anyFound = false;

    // 3. Preparar la llamada a la Chrome Policy API
    const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
    const payload = {
      policyTargetKey: {
        targetResource: targetResource
      },
      policySchemaFilter: "chrome.users.RendererCodeIntegrity",
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

    Logger.log("[ID-165] Solicitando política chrome.users.RendererCodeIntegrity...");
    try {
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      Logger.log(`[ID-165 - DETALLE API] HTTP Code: ${code}`);
      Logger.log(`[ID-165 - DETALLE API] RAW JSON: ${text}`);

      if (code === 200) {
        const json = JSON.parse(text);
        const resolvedPolicies = json.resolvedPolicies || [];
        
        if (resolvedPolicies.length > 0) {
          anyFound = true;
          resolvedPolicies.forEach((policy) => {
            const val = policy.value && policy.value.value;
            // Se valida extrayendo el campo en camelCase corregido
            if (val && val.rendererCodeIntegrityEnabled !== undefined) {
              rendererCodeIntegrityEnabled = val.rendererCodeIntegrityEnabled;
              Logger.log(`[ID-165 - PARSEO] Encontrada variable 'rendererCodeIntegrityEnabled'. Valor: ${rendererCodeIntegrityEnabled}`);
            }
          });
        } else {
          Logger.log("[ID-165 - INFO] La API no devolvió políticas explícitas. Chrome aplicará su comportamiento nativo (Habilitado por defecto).");
        }
      } else {
        Logger.log(`[ID-165 - ERROR] Petición fallida a la API con HTTP ${code}`);
      }
    } catch (e) {
      Logger.log(`[ID-165 - ERROR EXCEPCIÓN] Fallo de red: ${e.message}`);
    }

    // 4. Lógica de Riesgos y Construcción de la Respuesta
    let riesgo165, comentario165, valorPrincipal;

    if (rendererCodeIntegrityEnabled === true) {
      riesgo165 = "Bajo";
      valorPrincipal = "Habilitado (Forzado)";
      comentario165 = "La integridad del código del renderizador está explícitamente forzada. Esto previene eficazmente que software de terceros o código no firmado mitigue el aislamiento de los procesos de Chrome, bloqueando ataques de inyección de código local.";
    } else if (rendererCodeIntegrityEnabled === false) {
      riesgo165 = "Alto";
      valorPrincipal = "Deshabilitado";
      comentario165 = "La integridad del código del renderizador está explícitamente DESACTIVADA por política. Esto expone al navegador a riesgos críticos de explotación, permitiendo que aplicaciones locales sin privilegios o código malicioso inyecten DLLs directamente dentro del espacio de memoria del renderizador de Chrome.";
    } else {
      // anyFound === false o rendererCodeIntegrityEnabled === null (No configurado)
      riesgo165 = "Medio";
      valorPrincipal = "No Configurado (Habilitado por defecto)";
      comentario165 = "La directiva no está configurada de manera explícita en la raíz. Aunque las versiones modernas de Chrome mantienen esta protección activa por defecto, la falta de una política restrictiva corporativa permite que los perfiles locales o modificadores locales puedan alterar la configuración de seguridad.";
    }

    Logger.log(`[ID-165] Diagnóstico Terminado. Valor Detectado: ${rendererCodeIntegrityEnabled} | Riesgo Asignado: ${riesgo165}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-165 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario165: comentario165,
      riesgo165: riesgo165,
      score165: this.calcularScoreDeRiesgo(riesgo165)
    };
  }

  /**
   * Mapeo de puntajes estándar.
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
    Logger.log(`[ID-165] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario165: `Ocurrió un error inesperado al procesar la API: ${msg}`,
      riesgo165: "Medio",
      score165: 2
    };
  }
}