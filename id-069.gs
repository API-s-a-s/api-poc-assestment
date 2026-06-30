/**
 * Estrategia para auditar la configuración de Gmail Web Offline.
 * ID-069: Gmail Web sin conexión.
 */
class GmailWebOfflineStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-069", 
        valueKey: "valorPrincipal",
        noteKey: "comentario069",
        riskKey: "riesgo069",
        scoreKey: "score069"
      }
    ];
    super("Gmail Web Offline Audit", configIDs);
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

    const offlinePolicies = policies.filter(p => p.setting && (
      (p.setting.type || "").endsWith("gmail.offline_web_access") || 
      (p.setting.type || "").endsWith("gmail.offline")
    ));
    let isOfflineEnabled = false;
    let dataSource = "Memory";
    let rawData = null;

    if (offlinePolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(offlinePolicies, offlinePolicies[0].setting.type);
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-069] Política raíz efectiva encontrada: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-069] valueNode extraído: ${JSON.stringify(valueNode)}`);
        if (valueNode.enableOfflineWebAccess === true || valueNode.state === 'ENABLED') {
          isOfflineEnabled = true;
        }
      }
    } else {
      Logger.log(`[LOG] Gmail Offline no encontrado en v1, intentando Fase 2 (Admin Reports)...`);
      const logResult = this.checkAdminReportsForSetting("Offline");
      if (logResult.found) {
        isOfflineEnabled = logResult.enabled === true || (logResult.newValue && logResult.newValue.toLowerCase() === "true");
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        // Asumimos Habilitado como "riesgo por defecto" si es la configuración estándar de consumo, o "Deshabilitado" dependiendo.
        // Google por defecto tiene Gmail Offline deshabilitado, así que asumimos eso.
        isOfflineEnabled = false;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let respuestaConcreta, riesgo069, comentario069;

    if (isOfflineEnabled) {
      respuestaConcreta = "Habilitado";
      riesgo069 = "Alto";
      comentario069 = `El acceso a Gmail Web sin conexión está habilitado (Fuente: ${dataSource}). Esta configuración permite que los correos electrónicos se descarguen y almacenen en la caché local del navegador. Si el dispositivo del usuario se ve comprometido o es compartido, un atacante podría extraer información confidencial directamente del almacenamiento local sin necesidad de autenticación.`;
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo069 = "Bajo";
      comentario069 = `El acceso a Gmail Web sin conexión está deshabilitado (Fuente: ${dataSource}). No se permite que los correos se almacenen localmente en la caché del navegador, lo que protege contra la extracción de datos en dispositivos comprometidos o de uso compartido.`;
    }

    Logger.log(`[LOG] Gmail Offline Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo069}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario069: comentario069,
      riesgo069: riesgo069,
      score069: this.calcularScoreDeRiesgo(riesgo069)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo069: "Medio", score069: 2, comentario069: msg };
  }
}
