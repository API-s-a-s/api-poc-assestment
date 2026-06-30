/**
 * Estrategia para auditar la configuración de Filtrado Agresivo de Spam.
 * ID-079: Filtrado agresivo de spam.
 */
class GmailAggressiveSpamStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-079", 
        valueKey: "valorPrincipal",
        noteKey: "comentario079",
        riskKey: "riesgo079",
        scoreKey: "score079"
      }
    ];
    super("Gmail Aggressive Spam Filter Audit", configIDs);
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
      
      const response = AdminReports.Activities.list("all", "admin", {
        eventName: "CHANGE_GMAIL_SETTING",
        startTime: sixMonthsAgo.toISOString(),
        maxResults: 50
      });
      
      if (response.items && response.items.length > 0) {
        for (const item of response.items) {
          for (const event of item.events) {
            if (event.name === "CHANGE_GMAIL_SETTING") {
              const paramName = event.parameters.find(p => p.name === "SETTING_NAME");
              const paramEnabled = event.parameters.find(p => p.name === "SETTING_ENABLED");
              const paramNewValue = event.parameters.find(p => p.name === "NEW_VALUE");
              
              if (paramName && paramName.value && paramName.value.toLowerCase().includes(settingName.toLowerCase())) {
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
      return { found: false };
    } catch (e) {
      Logger.log(`[WARN] Reports API fallback failed: ${e.message}`);
      return { found: false, error: e.message };
    }
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    // Muchas configuraciones de spam se engloban en 'gmail.spam' o variantes.
    const spamPolicies = policies.filter(p => p.setting && ((p.setting.type || "").endsWith("gmail.spam") || (p.setting.type || "").endsWith("gmail.aggressive_spam")));
    let isAggressiveEnabled = false;
    let dataSource = "Memory";
    let rawData = null;

    if (spamPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(spamPolicies, spamPolicies[0].setting.type);
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-079] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-079] valueNode: ${JSON.stringify(valueNode)}`);
        if (valueNode.enableAggressiveSpamFilter === true || valueNode.aggressiveSpamFiltering === true) {
          isAggressiveEnabled = true;
        }
      }
    } else {
      Logger.log(`[LOG] Aggressive Spam no encontrado en v1, intentando Fase 2 (Admin Reports)...`);
      const logResult = this.checkAdminReportsForSetting("Aggressive spam");
      if (logResult.found) {
        isAggressiveEnabled = logResult.enabled === true || (logResult.newValue && logResult.newValue.toLowerCase() === "true");
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        // Por defecto, el filtrado agresivo está deshabilitado (ya que causa falsos positivos)
        isAggressiveEnabled = false;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let respuestaConcreta, riesgo079, comentario079;

    if (isAggressiveEnabled) {
      // Generalmente debe estar deshabilitada a menos que sea estrictamente necesario.
      respuestaConcreta = "Habilitado";
      riesgo079 = "Medio";
      comentario079 = `El filtrado agresivo de spam se encuentra habilitado (Fuente: ${dataSource}). Aunque esta configuración rechaza correos sospechosos en lugar de enviarlos a la carpeta de spam, aumenta la probabilidad de falsos positivos y pérdida de correos legítimos críticos. Solo se recomienda habilitar temporalmente durante campañas de spam severas contra la organización.`;
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo079 = "Bajo";
      comentario079 = `El filtrado agresivo de spam está deshabilitado (Fuente: ${dataSource}). Esto es acorde a las mejores prácticas de disponibilidad de correo, permitiendo que los controles predeterminados gestionen la reputación sin rechazar agresivamente mensajes que podrían ser falsos positivos.`;
    }

    Logger.log(`[LOG] Aggressive Spam Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo079}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario079: comentario079,
      riesgo079: riesgo079,
      score079: this.calcularScoreDeRiesgo(riesgo079)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo079: "Medio", score079: 2, comentario079: msg };
  }
}
