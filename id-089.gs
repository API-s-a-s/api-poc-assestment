/**
 * Estrategia para auditar la configuración de Gateway de salida.
 * ID-089: Gateway de salida.
 */
class GmailOutboundGatewayStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-089", 
        valueKey: "valorPrincipal",
        noteKey: "comentario089",
        riskKey: "riesgo089",
        scoreKey: "score089"
      }
    ];
    super("Gmail Outbound Gateway Audit", configIDs);
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
      Logger.log(`[DEBUG ID-089] Iniciando checkAdminReportsForSetting para: ${settingName}. Buscando desde: ${sixMonthsAgo.toISOString()}`);
      
      const response = AdminReports.Activities.list("all", "admin", {
        eventName: "CHANGE_GMAIL_SETTING",
        startTime: sixMonthsAgo.toISOString(),
        maxResults: 50
      });
      
      Logger.log(`[DEBUG ID-089] Respuesta de AdminReports obtenida. Items: ${response.items ? response.items.length : 0}`);
      
      if (response.items && response.items.length > 0) {
        for (const item of response.items) {
          for (const event of item.events) {
            if (event.name === "CHANGE_GMAIL_SETTING") {
              const paramName = event.parameters.find(p => p.name === "SETTING_NAME");
              const paramEnabled = event.parameters.find(p => p.name === "SETTING_ENABLED");
              const paramNewValue = event.parameters.find(p => p.name === "NEW_VALUE");
              
              if (paramName && paramName.value && paramName.value.toLowerCase().includes(settingName.toLowerCase())) {
                Logger.log(`[DEBUG ID-089] Coincidencia encontrada en AdminReports. Parámetros: SETTING_NAME=${paramName.value}, ENABLED=${paramEnabled ? paramEnabled.boolValue : 'N/A'}, NEW_VALUE=${paramNewValue ? paramNewValue.value : 'N/A'}`);
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
      Logger.log(`[DEBUG ID-089] No se encontraron configuraciones en AdminReports para: ${settingName}`);
      return { found: false };
    } catch (e) {
      Logger.log(`[WARN] Reports API fallback failed: ${e.message}`);
      return { found: false, error: e.message };
    }
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    Logger.log(`[DEBUG ID-089] Iniciando evaluateInMemory. Total políticas recibidas: ${policies.length}`);
    const outboundPolicies = policies.filter(p => p.setting && ((p.setting.type || "").includes("outbound") || (p.setting.type || "").includes("gateway")));
    Logger.log(`[DEBUG ID-089] Políticas de Gmail Outbound Gateway filtradas: ${outboundPolicies.length}`);

    let isOutboundConfigured = false;
    let dataSource = "Memory";
    let rawData = null;

    if (outboundPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(outboundPolicies, outboundPolicies[0].setting.type);
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-089] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-089] valueNode: ${JSON.stringify(valueNode)}`);
        if (valueNode.gatewayIp || valueNode.outboundGatewayHost || (valueNode.routes && valueNode.routes.length > 0)) {
          isOutboundConfigured = true;
        }
      }
    } else {
      Logger.log(`[LOG] Outbound gateway no encontrado en v1, intentando Fase 2 (Admin Reports)...`);
      const logResult = this.checkAdminReportsForSetting("Outbound gateway");
      if (logResult.found) {
        isOutboundConfigured = logResult.enabled === true || (logResult.newValue && logResult.newValue !== "");
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        isOutboundConfigured = false;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let respuestaConcreta, riesgo089, comentario089;

    if (isOutboundConfigured) {
      respuestaConcreta = "Habilitado";
      riesgo089 = "Medio"; // Riesgo medio porque requiere auditoría para asegurar que el appliance tercero es seguro y soporta TLS.
      comentario089 = `Se ha detectado un Gateway de Salida configurado Fuente: ${dataSource}.`;
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo089 = "Bajo";
      comentario089 = `No se detectó un Gateway de Salida configurado Fuente: ${dataSource}.`;
    }

    Logger.log(`[LOG] Outbound Gateway Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo089} | Fuente: ${dataSource}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario089: comentario089,
      riesgo089: riesgo089,
      score089: this.calcularScoreDeRiesgo(riesgo089)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo089: "Medio", score089: 2, comentario089: msg };
  }
}
