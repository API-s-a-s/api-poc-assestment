/**
 * Estrategia de Auditoría para Endpoint Verification (ID-162).
 * Evalúa si la extensión oficial de Google Endpoint Verification está force-installed
 * en la raíz del dominio mediante la Chrome Policy API.
 *
 * ID Evaluado: ID-162
 * Configuración Evaluada: Política de instalación de Endpoint Verification
 * Filtro de Esquema / Búsqueda: chrome.users.apps.ManagedApps (lista de extensiones forzadas)
 * Variable de Configuración: Se busca el ID de extensión 'callobklhcbilhphinckomhgkigpdnl'
 *
 * Nota Técnica: Endpoint Verification no tiene un toggle directo en la Chrome Policy API.
 * Su despliegue se controla exclusivamente forzando la instalación de la extensión oficial
 * de Google (ID: callobklhcbilhphinckomhgkigpdnl) vía política de extensiones forzadas.
 * Por ello, auditamos si la extensión está presente en la lista de extensiones force-installed.
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

    super("Chrome Endpoint Verification Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Gestión de navegadores";
    // ID oficial de la extensión Endpoint Verification de Google LLC
    this.ENDPOINT_VERIFICATION_EXT_ID = "callobklhcbilhphinckomhgkigpdnl";
  }

  /**
   * Evalúa si la extensión de Endpoint Verification está force-installed vía Chrome Policy API.
   * Estrategia: Consulta múltiples esquemas de extensiones forzadas para maximizar la detección.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-162 (ENDPOINT VERIFICATION) ==========");

    // 1. Obtener Token DWD
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

    // 2. Mapeo Robusto de la OU raíz
    let rootOuId = "";
    try {
      const response = AdminDirectory.Orgunits.list(this.customerId, { type: "all" });
      const orgUnits = response.organizationUnits || [];
      
      const childOfRoot = orgUnits.find(ou => ou.parentOrgUnitPath === "/");
      if (childOfRoot && childOfRoot.parentOrgUnitId) {
        rootOuId = childOfRoot.parentOrgUnitId.replace(/^id:/, "");
        Logger.log(`[ID-162] Raíz resuelta por hija directa: ${rootOuId}`);
      } else if (orgUnits.length > 0) {
        const anyOuWithParent = orgUnits.find(ou => ou.parentOrgUnitId);
        if (anyOuWithParent) {
          rootOuId = anyOuWithParent.parentOrgUnitId.replace(/^id:/, "");
          Logger.log(`[ID-162] Raíz resuelta por OU genérica: ${rootOuId}`);
        }
      }
    } catch (e) {
      Logger.log(`[ID-162 - WARN] No se pudo mapear la raíz vía AdminDirectory: ${e.message}`);
    }

    if (!rootOuId && this.customerId && this.customerId !== "my_customer") {
      rootOuId = this.customerId;
    }

    // Bloqueo preventivo de 404
    if (!rootOuId || rootOuId === "my_customer") {
      Logger.log("[ID-162 - ERROR CRÍTICO] No se pudo obtener el ID real de la OU.");
      return this._buildErrorResponse("No se pudo resolver el ID de la OU raíz (Se bloqueó la petición para evitar Error 404).");
    }

    const targetResource = `orgunits/${rootOuId}`;
    Logger.log(`[ID-162] Target Resource definitivo para la API: ${targetResource}`);

    let extensionFound = false;
    let installationType = null;

    // 3. Consultar directamente si la extensión de Endpoint Verification está configurada
    //    vía Chrome Policy API con el esquema chrome.users.apps.InstallType
    //    usando additionalTargetKeys con el app_id específico.
    const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;

    Logger.log("[ID-162] Intentando consulta directa por app_id del Endpoint Verification...");
    try {
      const directPayload = {
        policyTargetKey: {
          targetResource: targetResource,
          additionalTargetKeys: {
            app_id: `chrome:${this.ENDPOINT_VERIFICATION_EXT_ID}`
          }
        },
        policySchemaFilter: "chrome.users.apps.InstallType",
        pageSize: 10
      };

      const directOptions = {
        method: "post",
        headers: {
          ...dwdHeader,
          "Content-Type": "application/json",
          "Cache-Control": "no-cache"
        },
        payload: JSON.stringify(directPayload),
        muteHttpExceptions: true
      };

      const directResponse = UrlFetchApp.fetch(url, directOptions);
      const directCode = directResponse.getResponseCode();
      const directText = directResponse.getContentText();

      Logger.log(`[ID-162 - CONSULTA DIRECTA] HTTP ${directCode}: ${directText}`);

      if (directCode === 200) {
        const directJson = JSON.parse(directText);
        const directPolicies = directJson.resolvedPolicies || [];
        
        if (directPolicies.length > 0) {
          extensionFound = true;
          const val = directPolicies[0].value && directPolicies[0].value.value;
          if (val && val.appInstallType) {
            installationType = val.appInstallType;
          }
          Logger.log(`[ID-162 - MATCH DIRECTO] Endpoint Verification detectado. InstallType: ${installationType}`);
        }
      }
    } catch (e) {
      Logger.log(`[ID-162 - WARN] Consulta directa por app_id falló: ${e.message}`);
    }

    // 4. Fallback: Consultar la lista genérica de extensiones forzadas
    if (!extensionFound) {
      const fallbackSchemas = [
        "chrome.users.apps.ManagedApps",
        "chrome.users.ExtensionInstallForcelist"
      ];

      for (const schema of fallbackSchemas) {
        if (extensionFound) break;

        const payload = {
          policyTargetKey: {
            targetResource: targetResource
          },
          policySchemaFilter: schema,
          pageSize: 200
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

        Logger.log(`[ID-162] Consultando esquema fallback: ${schema}...`);
        try {
          const response = UrlFetchApp.fetch(url, options);
          const code = response.getResponseCode();
          const text = response.getContentText();
          
          Logger.log(`[ID-162 - DETALLE API] HTTP ${code} para esquema ${schema}`);
          Logger.log(`[ID-162 - DETALLE API] RAW (primeros 2000 chars): ${text.substring(0, 2000)}`);

          if (code === 200) {
            const json = JSON.parse(text);
            const resolvedPolicies = json.resolvedPolicies || [];
            
            for (const policy of resolvedPolicies) {
              const fullText = JSON.stringify(policy);
              if (fullText.includes(this.ENDPOINT_VERIFICATION_EXT_ID)) {
                extensionFound = true;
                const policyAppId = (policy.targetKey && policy.targetKey.additionalTargetKeys && 
                                    policy.targetKey.additionalTargetKeys.app_id) || "";
                const val = policy.value && policy.value.value;
                if (val && (val.installationType || val.installType || val.appInstallType)) {
                  installationType = val.installationType || val.installType || val.appInstallType;
                } else if (policyAppId.includes(this.ENDPOINT_VERIFICATION_EXT_ID)) {
                  installationType = "FORCED (detectada como app gestionada)";
                }
                Logger.log(`[ID-162 - MATCH] Extensión encontrada en esquema ${schema}. Tipo: ${installationType || "No determinado"}`);
                break;
              }
            }
            
            if (!extensionFound) {
              Logger.log(`[ID-162 - INFO] Extensión NO encontrada en ${schema}. Políticas evaluadas: ${resolvedPolicies.length}`);
            }
          } else if (code === 404) {
            Logger.log(`[ID-162 - WARN] Esquema ${schema} no encontrado (HTTP 404).`);
          } else {
            Logger.log(`[ID-162 - ERROR] HTTP ${code} para esquema ${schema}`);
          }
        } catch (e) {
          Logger.log(`[ID-162 - ERROR EXCEPCIÓN] Fallo al consultar ${schema}: ${e.message}`);
        }
      }
    }

    // 5. Lógica de Riesgos y Construcción de la Respuesta
    let riesgo162, comentario162, valorPrincipal;

    if (extensionFound) {
      const installStr = installationType ? ` (Tipo: ${installationType})` : "";
      riesgo162 = "Bajo";
      valorPrincipal = "Habilitado (Force-Installed)";
      comentario162 = `La extensión oficial de Endpoint Verification de Google (ID: ${this.ENDPOINT_VERIFICATION_EXT_ID}) se encuentra instalada de forma forzada por política corporativa en la OU raíz${installStr}. Esto permite recopilar señales de confianza del dispositivo (estado del cifrado de disco, versión de SO, estado de bloqueo de pantalla) y habilita los controles de Acceso Contextual (CAA) basados en la postura del dispositivo. Es una práctica esencial para arquitecturas de seguridad Zero Trust.`;
    } else {
      riesgo162 = "Alto";
      valorPrincipal = "No Instalado / Sin Política";
      comentario162 = `La extensión de Endpoint Verification (ID: ${this.ENDPOINT_VERIFICATION_EXT_ID}) NO se encontró en las listas de extensiones forzadas de la OU raíz. Sin esta extensión desplegada, la organización no puede recopilar señales de confianza de los dispositivos ni aplicar políticas de Acceso Contextual (Context-Aware Access) basadas en la postura del endpoint, lo que debilita significativamente la verificación de cumplimiento y los controles de seguridad Zero Trust.`;
    }

    Logger.log(`[ID-162] Diagnóstico Terminado. Extensión encontrada: ${extensionFound} | Riesgo: ${riesgo162}`);
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
