/**
 * Configuración Evaluada: Restricciones de descarga
 * Filtro de Esquema / Búsqueda: chrome.users.DownloadRestrictions
 * Variable de Configuración Real API: safeBrowsingDownloadRestrictions (Confirmado en Logs)
 */
class ChromeDownloadRestrictionsStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-168",
        valueKey: "valorPrincipal",
        noteKey: "comentario168",
        riskKey: "riesgo168",
        scoreKey: "score168"
      }
    ];

    super("Chrome Download Restrictions Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Gestión de navegadores";
  }

  /**
   * Evalúa la política 'chrome.users.DownloadRestrictions' en la raíz del dominio.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-168 (DOWNLOAD RESTRICTIONS) ==========");

    // 1. Obtener Token DWD
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[ID-168] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[ID-168 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
      return this._buildErrorResponse(`Fallo al generar token DWD: ${e.message}`);
    }

    // 2. Mapeo Robusto de la OU raíz (Estrategias A, B y C para evitar Error 404)
    let rootOuId = "";
    try {
      const response = AdminDirectory.Orgunits.list(this.customerId, { type: "all" });
      const orgUnits = response.organizationUnits || [];
      
      const childOfRoot = orgUnits.find(ou => ou.parentOrgUnitPath === "/");
      if (childOfRoot && childOfRoot.parentOrgUnitId) {
        rootOuId = childOfRoot.parentOrgUnitId.replace(/^id:/, "");
        Logger.log(`[ID-168] Raíz resuelta por hija directa: ${rootOuId}`);
      } else if (orgUnits.length > 0) {
        const anyOuWithParent = orgUnits.find(ou => ou.parentOrgUnitId);
        if (anyOuWithParent) {
          rootOuId = anyOuWithParent.parentOrgUnitId.replace(/^id:/, "");
          Logger.log(`[ID-168] Raíz resuelta por UO genérica: ${rootOuId}`);
        }
      }
    } catch (e) {
      Logger.log(`[ID-168 - WARN] No se pudo mapear la raíz vía AdminDirectory: ${e.message}`);
    }

    if (!rootOuId && this.customerId && this.customerId !== "my_customer") {
      rootOuId = this.customerId;
    }

    // Bloqueo preventivo de 404
    if (!rootOuId || rootOuId === "my_customer") {
      Logger.log("[ID-168 - ERROR CRÍTICO] No se pudo obtener el ID real de la OU.");
      return this._buildErrorResponse("No se pudo resolver el ID de la OU raíz (Se bloqueó la petición para evitar Error 404).");
    }

    const targetResource = `orgunits/${rootOuId}`;
    Logger.log(`[ID-168] Target Resource definitivo para la API: ${targetResource}`);

    let downloadRestrictionsValue = null;
    let anyFound = false;

    // 3. Preparar la llamada a la Chrome Policy API
    const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
    const payload = {
      policyTargetKey: {
        targetResource: targetResource
      },
      policySchemaFilter: "chrome.users.DownloadRestrictions",
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

    Logger.log("[ID-168] Solicitando política chrome.users.DownloadRestrictions...");
    try {
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      Logger.log(`[ID-168 - DETALLE API] HTTP Code: ${code}`);
      Logger.log(`[ID-168 - DETALLE API] RAW JSON: ${text}`);

      if (code === 200) {
        const json = JSON.parse(text);
        const resolvedPolicies = json.resolvedPolicies || [];
        
        if (resolvedPolicies.length > 0) {
          anyFound = true;
          resolvedPolicies.forEach((policy) => {
            const val = policy.value && policy.value.value;
            if (val) {
              // Mapeo adaptativo: prioriza la variable real observada en tus logs corporativos
              if (val.safeBrowsingDownloadRestrictions !== undefined) {
                downloadRestrictionsValue = val.safeBrowsingDownloadRestrictions;
                Logger.log(`[ID-168 - PARSEO] Encontrada variable real 'safeBrowsingDownloadRestrictions'. Valor: ${downloadRestrictionsValue}`);
              } else if (val.downloadRestrictions !== undefined) {
                downloadRestrictionsValue = val.downloadRestrictions;
                Logger.log(`[ID-168 - PARSEO] Encontrada variable alternativa 'downloadRestrictions'. Valor: ${downloadRestrictionsValue}`);
              }
            }
          });
        } else {
          Logger.log("[ID-168 - INFO] La API no devolvió restricciones de descarga explícitas en la raíz. Chrome heredará el comportamiento por defecto (Permitir descargas).");
        }
      } else {
        Logger.log(`[ID-168 - ERROR] Petición fallida a la API con HTTP ${code}`);
      }
    } catch (e) {
      Logger.log(`[ID-168 - ERROR EXCEPCIÓN] Fallo de red: ${e.message}`);
    }

    // 4. Lógica de Riesgos y Construcción de la Respuesta
    // Valores estándar del ENUM de restricciones de Google Chrome:
    // - "DOWNLOAD_RESTRICTION_ENUM_NONE" (0): Sin restricciones
    // - "DOWNLOAD_RESTRICTION_ENUM_BLOCK_DANGEROUS_DOWNLOAD" (1): Bloquear descargas declaradas como maliciosas
    // - "DOWNLOAD_RESTRICTION_ENUM_BLOCK_POTENTIALLY_DANGEROUS_DOWNLOAD" (2): Bloquear descargas sospechosas o de baja reputación
    // - "DOWNLOAD_RESTRICTION_ENUM_BLOCK_ALL_DOWNLOAD" (3): Bloquear absolutamente todas las descargas
    // - "DOWNLOAD_RESTRICTION_ENUM_BLOCK_MALICIOUS_DOWNLOAD" (4): Bloqueo estricto de malware confirmado
    
    let riesgo168, comentario168, valorPrincipal;

    if (!anyFound || downloadRestrictionsValue === null) {
      riesgo168 = "Alto";
      valorPrincipal = "Sin Configurar (Hereda por defecto)";
      comentario168 = "La Chrome Policy API respondió exitosamente indicando que no hay restricciones de descarga configuradas explícitamente en la OU raíz. Chrome permite de forma nativa cualquier descarga, transfiriendo la responsabilidad de identificar malware al usuario final (Riesgo de Ransomware).";
    } else {
      const restStr = downloadRestrictionsValue.toString();

      if (restStr.includes("BLOCK_POTENTIALLY_DANGEROUS") || restStr.includes("BLOCK_ALL") || restStr === "2" || restStr === "3") {
        riesgo168 = "Bajo";
        valorPrincipal = restStr.includes("ALL") ? "Bloqueo Total" : "Bloqueo Preventivo Amplio (Seguro)";
        comentario168 = `Las restricciones de descarga están configuradas de forma óptima (${restStr}). El navegador bloqueará automáticamente archivos sospechosos, descargas no deseadas o ejecutables de baja reputación antes de que toquen el almacenamiento del dispositivo.`;
      } else if (restStr.includes("NONE") || restStr === "0") {
        riesgo168 = "Alto";
        valorPrincipal = "Sin Restricciones Explícito";
        comentario168 = "La política está configurada explícitamente para permitir todo tipo de descargas. Esto anula los filtros proactivos del navegador y expone a la organización a incidentes de Ransomware o inyección de código mediante descargas automáticas ('drive-by downloads').";
      } else {
        // Bloqueo básico de malware confirmado ("BLOCK_DANGEROUS" / "BLOCK_MALICIOUS")
        riesgo168 = "Medio";
        valorPrincipal = "Bloqueo Básico de Amenazas";
        comentario168 = `La política tiene un nivel de restricción moderado (${restStr}). Bloquea amenazas confirmadas, pero no protege el entorno contra archivos adjuntos sospechosos, archivos comprimidos sin reputación o extensiones no analizadas. Se recomienda elevar al nivel 'BLOCK_POTENTIALLY_DANGEROUS_DOWNLOAD'.`;
      }
    }

    Logger.log(`[ID-168] Diagnóstico Terminado. Valor Detectado: ${downloadRestrictionsValue} | Riesgo Asignado: ${riesgo168}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-168 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario168: comentario168,
      riesgo168: riesgo168,
      score168: this.calcularScoreDeRiesgo(riesgo168)
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
    Logger.log(`[ID-168] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario168: `Ocurrió un error inesperado al procesar la API: ${msg}`,
      riesgo168: "Medio",
      score168: 2
    };
  }
}