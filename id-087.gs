/**
 * Estrategia para auditar el cumplimiento de transporte seguro TLS.
 * ID-087: Reglas de cumplimiento de transporte seguro (TLS).
 */
class GmailTlsComplianceStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-087", 
        valueKey: "valorPrincipal",
        noteKey: "comentario087",
        riskKey: "riesgo087",
        scoreKey: "score087"
      }
    ];
    super("Gmail TLS Compliance Audit", configIDs);
    this.category = "Email y DNS";
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  checkAdminReportsForSetting(settingName) {
    try {
      const sixMonthsAgo = new Date();
      sixMonthsAgo.setDate(sixMonthsAgo.getDate() - 180);
      Logger.log(`[DEBUG ID-087] Iniciando checkAdminReportsForSetting para: ${settingName}. Buscando desde: ${sixMonthsAgo.toISOString()}`);
      
      const response = AdminReports.Activities.list("all", "admin", {
        eventName: "CHANGE_GMAIL_SETTING",
        startTime: sixMonthsAgo.toISOString(),
        maxResults: 50
      });
      
      Logger.log(`[DEBUG ID-087] Respuesta de AdminReports obtenida. Items: ${response.items ? response.items.length : 0}`);
      
      if (response.items && response.items.length > 0) {
        for (const item of response.items) {
          for (const event of item.events) {
            if (event.name === "CHANGE_GMAIL_SETTING") {
              const paramName = event.parameters.find(p => p.name === "SETTING_NAME");
              const paramEnabled = event.parameters.find(p => p.name === "SETTING_ENABLED");
              const paramNewValue = event.parameters.find(p => p.name === "NEW_VALUE");
              
              if (paramName && paramName.value && paramName.value.toLowerCase().includes(settingName.toLowerCase())) {
                Logger.log(`[DEBUG ID-087] Coincidencia encontrada en AdminReports. Parámetros: SETTING_NAME=${paramName.value}, ENABLED=${paramEnabled ? paramEnabled.boolValue : 'N/A'}, NEW_VALUE=${paramNewValue ? paramNewValue.value : 'N/A'}`);
                return {
                  found: true,
                  enabled: paramEnabled ? paramEnabled.boolValue : null,
                  newValue: paramNewValue ? paramNewValue.value : null,
                  raw: item
                };
              }
            }
          }
        }
      }
      Logger.log(`[DEBUG ID-087] No se encontraron configuraciones en AdminReports para: ${settingName}`);
      return { found: false };
    } catch (e) {
      Logger.log(`[WARN] Reports API fallback failed: ${e.message}`);
      return { found: false, error: e.message };
    }
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    Logger.log(`[DEBUG ID-087] Iniciando evaluateInMemory. Total políticas recibidas: ${policies.length}`);
    const tlsPolicies = policies.filter(p => p.setting && ((p.setting.type || "").includes("tls") || (p.setting.type || "").includes("secure_transport")));
    Logger.log(`[DEBUG ID-087] Políticas de Gmail TLS Compliance filtradas: ${tlsPolicies.length}`);

    let rulesCount = 0;
    let dataSource = "Memory";
    let rawData = null;

    if (tlsPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(tlsPolicies, tlsPolicies[0].setting.type);
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-087] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-087] valueNode: ${JSON.stringify(valueNode)}`);
        const rules = valueNode.rules || valueNode.settingRules || valueNode.tlsRules || [];
        Logger.log(`[DEBUG ID-087] Reglas TLS detectadas: ${rules.length}`);
        rulesCount = rules.length;
      }
    } else {
      Logger.log(`[LOG] Secure transport no encontrado en v1, intentando Fase 2 (Admin Reports)...`);
      const logResult = this.checkAdminReportsForSetting("Secure transport");
      if (logResult.found) {
        rulesCount = (logResult.enabled === true || (logResult.newValue && logResult.newValue !== "")) ? 1 : 0;
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        rulesCount = 0;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let riesgo087, comentario087;

    if (rulesCount > 0) {
      riesgo087 = "Bajo";
      comentario087 = `Se encontraron ${rulesCount} reglas de Cumplimiento TLS`;
    } else {
      riesgo087 = "Medio";
      comentario087 = `No se detectaron reglas explícitas de cumplimiento de transporte seguro TLS.`;
    }

    Logger.log(`[LOG] TLS Compliance Audit: ${rulesCount} reglas detectadas. | Riesgo: ${riesgo087} | Fuente: ${dataSource}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: rulesCount,
      comentario087: comentario087,
      riesgo087: riesgo087,
      score087: this.calcularScoreDeRiesgo(riesgo087)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo087: "Medio", score087: 2, comentario087: msg };
  }
}
