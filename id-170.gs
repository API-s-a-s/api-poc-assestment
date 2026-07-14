/**
 * Estrategia de Auditoría para las Actualizaciones de Componentes de Chrome (ID-170).
 * Filtro de Esquema / Búsqueda: chrome.users.ComponentUpdatesEnabled
 * Variable de Configuración Real API: componentUpdatesEnabled (camelCase)
 */
class ChromeComponentUpdatesStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-170",
        valueKey: "valorPrincipal",
        noteKey: "comentario170",
        riskKey: "riesgo170",
        scoreKey: "score170"
      }
    ];

    super("Chrome Component Updates Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Gestión de navegadores";
  }

  /**
   * Evalúa la política 'chrome.users.ComponentUpdatesEnabled' en la raíz del dominio.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-170 (COMPONENT UPDATES) ==========");

    // 1. Obtener Token DWD
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[ID-170] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[ID-170 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
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
        Logger.log(`[ID-170] Raíz resuelta por hija directa: ${rootOuId}`);
      } 
      // B: Buscar cualquier OU que tenga un padre
      else if (orgUnits.length > 0) {
        const anyOuWithParent = orgUnits.find(ou => ou.parentOrgUnitId);
        if (anyOuWithParent) {
          rootOuId = anyOuWithParent.parentOrgUnitId.replace(/^id:/, "");
          Logger.log(`[ID-170] Raíz resuelta por OU genérica: ${rootOuId}`);
        }
      }
    } catch (e) {
      Logger.log(`[ID-170 - WARN] No se pudo mapear la raíz vía AdminDirectory: ${e.message}`);
    }

    // C: Usar el customerId solo si es un formato canónico (ej: 03ph...) y no "my_customer"
    if (!rootOuId && this.customerId && this.customerId !== "my_customer") {
      rootOuId = this.customerId;
    }

    // Bloqueo preventivo de 404
    if (!rootOuId || rootOuId === "my_customer") {
      Logger.log("[ID-170 - ERROR CRÍTICO] No se pudo obtener el ID real de la OU.");
      return this._buildErrorResponse("No se pudo resolver el ID de la OU raíz (Se bloqueó la petición para evitar Error 404).");
    }

    const targetResource = `orgunits/${rootOuId}`;
    Logger.log(`[ID-170] Target Resource definitivo para la API: ${targetResource}`);

    let componentUpdatesEnabled = null;
    let anyFound = false;
    let schemaNotFound = false;

    // 3. Preparar la llamada a la Chrome Policy API
    const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
    const payload = {
      policyTargetKey: {
        targetResource: targetResource
      },
      policySchemaFilter: "chrome.users.ComponentUpdatesEnabled",
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

    Logger.log("[ID-170] Solicitando política chrome.users.ComponentUpdatesEnabled...");
    try {
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      Logger.log(`[ID-170 - DETALLE API] HTTP Code: ${code}`);
      Logger.log(`[ID-170 - DETALLE API] RAW JSON: ${text}`);

      if (code === 200) {
        const json = JSON.parse(text);
        const resolvedPolicies = json.resolvedPolicies || [];
        
        if (resolvedPolicies.length > 0) {
          anyFound = true;
          resolvedPolicies.forEach((policy) => {
            const val = policy.value && policy.value.value;
            // Se valida extrayendo el campo en camelCase corregido
            if (val && val.componentUpdatesEnabled !== undefined) {
              componentUpdatesEnabled = val.componentUpdatesEnabled;
              Logger.log(`[ID-170 - PARSEO] Encontrada variable 'componentUpdatesEnabled'. Valor: ${componentUpdatesEnabled}`);
            }
          });
        } else {
          Logger.log("[ID-170 - INFO] La API no devolvió políticas explícitas en la raíz. Chrome aplicará su comportamiento nativo (Habilitado por defecto).");
        }
      } else if (code === 404) {
        schemaNotFound = true;
        Logger.log(`[ID-170 - WARN] Esquema no encontrado en la API (HTTP 404). Posible deprecación o namespace incorrecto.`);
      } else {
        Logger.log(`[ID-170 - ERROR] Petición fallida a la API con HTTP ${code}`);
      }
    } catch (e) {
      Logger.log(`[ID-170 - ERROR EXCEPCIÓN] Fallo de red: ${e.message}`);
    }

    // 4. Lógica de Riesgos y Construcción de la Respuesta
    let riesgo170, comentario170, valorPrincipal;

    if (schemaNotFound) {
      riesgo170 = "Medio";
      valorPrincipal = "No Disponible vía API";
      comentario170 = "El esquema de política no fue encontrado en la Chrome Policy API (HTTP 404). Es posible que la política haya sido deprecada, renombrada, o pertenezca a un nivel jerárquico diferente.";
    } else if (componentUpdatesEnabled === true) {
      riesgo170 = "Bajo";
      valorPrincipal = "Habilitado (Forzado)";
      comentario170 = "Las actualizaciones de componentes de Chrome están explícitamente habilitadas. Esto garantiza que el navegador reciba e instale de inmediato parches de seguridad fuera de banda, actualizaciones de listas de revocación de certificados (CRLSet) y submódulos de protección contra malware sin necesidad de esperar un reinicio completo del navegador.";
    } else if (componentUpdatesEnabled === false) {
      riesgo170 = "Alto";
      valorPrincipal = "Deshabilitado (Crítico)";
      comentario170 = "Las actualizaciones de componentes de Chrome se encuentran explícitamente DESACTIVADAS por política corporativa. Esto impide que el navegador mitigue amenazas de día cero de forma rápida o invalide certificados de seguridad comprometidos dinámicamente, incrementando drásticamente la superficie de exposición ante exploits dirigidos.";
    } else {
      // anyFound === false o componentUpdatesEnabled === null (No configurado)
      riesgo170 = "Bajo";
      valorPrincipal = "No Configurado (Habilitado por defecto / 0)";
      comentario170 = "La directiva no está configurada de manera explícita en la raíz del dominio. Aunque Chrome mantiene activas de forma nativa las actualizaciones automáticas de sus subcomponentes, se recomienda forzar la política de forma mandatoria para evitar modificaciones locales no autorizadas en el perfil del usuario.";
    }

    Logger.log(`[ID-170] Diagnóstico Terminado. Valor Detectado: ${componentUpdatesEnabled} | Riesgo Asignado: ${riesgo170}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-170 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario170: comentario170,
      riesgo170: riesgo170,
      score170: this.calcularScoreDeRiesgo(riesgo170)
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
    Logger.log(`[ID-170] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario170: `Ocurrió un error inesperado al procesar la API: ${msg}`,
      riesgo170: "Medio",
      score170: 2
    };
  }
}