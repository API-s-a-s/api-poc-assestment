/**
 * Estrategia de Auditoría para las Reglas de Informes de Seguridad (ID-178).
 * Evalúa el volumen y estado de las alertas generadas por reglas de actividad/informes
 * utilizando Alert Center API (v1beta1 - versión oficial de producción) y Reports API. 
 * Detecta problemas de "Fatiga de alertas" en el SOC.
 *
 * ID Evaluado: ID-178
 * Configuración Evaluada: Reglas de informes de seguridad y Notificaciones de Actividad
 */
class WorkspaceSecurityRulesStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-178",
        valueKey: "valorPrincipal",
        noteKey: "comentario178",
        riskKey: "riesgo178",
        scoreKey: "score178"
      }
    ];

    super("Workspace Security Rules Telemetry Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Preparar y supervisar";
  }

  /**
   * Evalúa las políticas consultando las APIs de Alertas y Reportes.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-178 (REGLAS DE SEGURIDAD Y ALERTAS) ==========");

    // 1. Obtener Token DWD con scopes para Alert Center y Reports API
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/apps.alerts",
        "https://www.googleapis.com/auth/admin.reports.audit.readonly"
      ]);
      Logger.log("[ID-178] Token DWD generado con éxito para Alert Center y Reports API.");
    } catch (e) {
      Logger.log(`[ID-178 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
      return this._buildErrorResponse(`Fallo al generar token DWD: ${e.message}. Asegúrate de tener los scopes auth/apps.alerts y auth/admin.reports.audit.readonly.`);
    }

    const options = {
      method: "get",
      headers: {
        ...dwdHeader,
        "Content-Type": "application/json",
        "Cache-Control": "no-cache"
      },
      muteHttpExceptions: true
    };

    // Acumuladores lógicos para Telemetría
    let totalAlerts = 0;
    let notStartedCount = 0;
    let activityRuleCount = 0;
    let dlpRuleCount = 0;
    let suspiciousCount = 0;
    let alertCenterSuccess = false;

    // 2. Consultar Alert Center API (v1beta1 - Es la ÚNICA versión de producción soportada por Google)
    const alertCenterUrl = `https://alertcenter.googleapis.com/v1beta1/alerts?pageSize=100`;
    Logger.log("[ID-178] Consultando Alert Center API (v1beta1 oficial)...");
    
    try {
      const response = UrlFetchApp.fetch(alertCenterUrl, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      Logger.log(`[ID-178 - ALERT CENTER] HTTP Code: ${code}`);
      
      if (code === 200) {
        alertCenterSuccess = true;
        const json = JSON.parse(text);
        const alerts = json.alerts || [];
        totalAlerts = alerts.length;
        
        alerts.forEach(alert => {
          const type = alert.type || "";
          const status = alert.status || "NOT_STARTED";

          // Clasificando el estado de la alerta (Investigando Fatiga)
          if (status === "NOT_STARTED") notStartedCount++;
          
          // Clasificando la Categoría de la Alerta
          if (type === "ActivityRule") activityRuleCount++;
          else if (type === "DlpRuleViolation") dlpRuleCount++;
          else if (type === "SuspiciousActivity") suspiciousCount++;
        });
        
        Logger.log(`[ID-178 - PARSEO ALERTAS] Total: ${totalAlerts} | No Iniciadas: ${notStartedCount} | ActivityRules: ${activityRuleCount} | DLP: ${dlpRuleCount}`);
      } else {
        Logger.log(`[ID-178 - ERROR] Alert Center falló con HTTP ${code}. Resp: ${text}`);
      }
    } catch (e) {
      Logger.log(`[ID-178 - ERROR EXCEPCIÓN] Fallo en Alert Center: ${e.message}`);
    }

    // 3. Consultar Reports API (Audit Logs de eventos originados por "rules")
    let totalRuleEvents = 0;
    let gmailEventsCount = 0;
    let driveEventsCount = 0;
    let reportsSuccess = false;
    
    const reportsUrl = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/rules?maxResults=100`;
    Logger.log("[ID-178] Consultando Reports API (applicationName=rules)...");
    
    try {
      const response = UrlFetchApp.fetch(reportsUrl, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      Logger.log(`[ID-178 - REPORTS] HTTP Code: ${code}`);
      
      if (code === 200) {
        reportsSuccess = true;
        const json = JSON.parse(text);
        const items = json.items || [];
        totalRuleEvents = items.length;
        
        items.forEach(item => {
          const events = item.events || [];
          events.forEach(ev => {
            const params = ev.parameters || [];
            // Buscar el vector del incidente en los parámetros del evento
            params.forEach(p => {
              if (p.value === "GMAIL_EVENTS") gmailEventsCount++;
              if (p.value === "DRIVE_EVENTS") driveEventsCount++;
            });
          });
        });
        
        Logger.log(`[ID-178 - PARSEO REPORTES] Disparos detectados: ${totalRuleEvents}. Drive Events: ${driveEventsCount}, Gmail Events: ${gmailEventsCount}.`);
      } else {
        Logger.log(`[ID-178 - ERROR] Reports API falló con HTTP ${code}. Resp: ${text}`);
      }
    } catch (e) {
      Logger.log(`[ID-178 - ERROR EXCEPCIÓN] Fallo en Reports API: ${e.message}`);
    }

    // 4. Lógica de Riesgos y Construcción de la Respuesta
    let riesgo178, comentario178, valorPrincipal;

    if (!alertCenterSuccess && !reportsSuccess) {
      return this._buildErrorResponse("Las APIs de Alert Center y Reports fallaron. Revisa los scopes DWD en la Consola de Admin.");
    }

    if (totalAlerts === 0 && totalRuleEvents === 0) {
      riesgo178 = "Alto";
      valorPrincipal = "Deshabilitado";
      comentario178 = "No se han registrado eventos de reglas de seguridad, ni alertas en el dominio, se perdiendo visibilidad sobre incidentes.";
    } else {
      // Determinando Fatiga de Alertas: 
      // Consideramos fatiga si hay una muestra representativa (> 10 alertas) y más del 50% son ignoradas ("NOT_STARTED")
      const fatigaAlertas = (totalAlerts > 10 && (notStartedCount / totalAlerts) >= 0.50);

      if (fatigaAlertas) {
        riesgo178 = "Medio";
        valorPrincipal = "Habilitado (Fatiga de alertas SOC)";
        comentario178 = `Las reglas de seguridad operan: Drive: ${driveEventsCount}, Gmail: ${gmailEventsCount}). De ${totalAlerts} alertas, ${notStartedCount} se mantienen en 'NOT_STARTED'. Se sugiere ajustar reglas condicionales de 'ActivityRule' y 'DLP' para reducir los falsos positivos.`;
      } else {
        riesgo178 = "Bajo";
        valorPrincipal = "Habilitado";
        comentario178 = `Se detectaron ${totalRuleEvents} disparos de reglas preventivas; en Drive: ${driveEventsCount}, Gmail: ${gmailEventsCount}).`;
      }
    }

    Logger.log(`[ID-178] Diagnóstico Terminado. Riesgo Asignado: ${riesgo178} | Valor: ${valorPrincipal}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-178 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario178: comentario178,
      riesgo178: riesgo178,
      score178: this.calcularScoreDeRiesgo(riesgo178)
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
    Logger.log(`[ID-178] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario178: `Ocurrió un error inesperado al procesar la API: ${msg}`,
      riesgo178: "Medio",
      score178: 2
    };
  }
}