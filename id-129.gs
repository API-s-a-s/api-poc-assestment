/**
 * Estrategia para auditar los niveles de moderación de spam en recursos individuales de Google Groups.
 * Evalúa el parámetro spamModerationLevel de forma granular por recurso.
 * Utiliza Google Groups Settings API (v1).
 * Endpoint: https://www.googleapis.com/groups/v1/groups/{groupUniqueId}
 */
class GroupsSpamModerationStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-129", 
        valueKey: "valorPrincipal",
        noteKey: "comentario129",
        riskKey: "riesgo129",
        scoreKey: "score129"
      }
    ];

    super("Groups Individual Spam Moderation Audit", configIDs);
    this.category = "Servicios adicionales";
    this.customerId = customerId;
  }

  // Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  evaluateInMemory(globalContext) {
    const { auth } = globalContext;
    // Captura resiliente de la lista de grupos cargada por el Core
    const groupsList = globalContext.groups || globalContext.allGroups || [];
    
    Logger.log(`[DEBUG ID-129] Total de grupos detectados en el contexto para evaluar: ${groupsList.length}`);

    if (!auth) return this._buildErrorResponse("Falta el objeto de autenticación ('auth') en el contexto global.");
    if (groupsList.length === 0) {
      Logger.log(`[ID-129] [WARNING] No se encontraron grupos en el contexto global para auditar.`);
      return {
        name: this.name,
        raw: null,
        valorPrincipal: "Sin grupos detectados",
        comentario129: "No se encontraron recursos instanciados de tipo Google Groups para analizar la moderación de spam.",
        riesgo129: "Bajo",
        score129: 3
      };
    }

    // Contadores de control para cuantificar el impacto (servicios afectados)
    let totalEvaluated = 0;
    let allowRiskCount = 0; // Cantidad de grupos vulnerables (ALLOW)
    let protectedCount = 0;  // Cantidad de grupos con moderación/bloqueo (MODERATE, SILENTLY_MODERATE, REJECT)
    let affectedGroupsDetails = [];

    // Credenciales privilegiadas para el alcance de configuración de grupos
    const adminEmail = auth.getCurrentUserEmail(); 
    const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
      "https://www.googleapis.com/auth/apps.groups.settings"
    ]);

    // Bucle para auditar de forma granular grupo por grupo
    for (let i = 0; i < groupsList.length; i++) {
      const groupItem = groupsList[i];
      const groupEmail = (typeof groupItem === 'object') ? (groupItem.email || groupItem.id) : groupItem;
      
      if (!groupEmail) {
        Logger.log(`[DEBUG ID-129] Índice ${i} saltado debido a formato de dirección inválido.`);
        continue;
      }

      totalEvaluated++;
      Logger.log(`[ID-129] [PROCESANDO ${totalEvaluated}/${groupsList.length}] Analizando políticas de spam para: ${groupEmail}`);

      try {
        const url = `https://www.googleapis.com/groups/v1/groups/${encodeURIComponent(groupEmail)}`;
        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const responseText = response.getContentText();
        
        // LOG EXPLICITO EXIGIDO: Imprimir exactamente el RAW text que envía la API de Google por cada recurso
        Logger.log(`[DEBUG ID-129] [RAW RESPONSE] Grupo: ${groupEmail} -> ${responseText}`);

        const groupSettings = JSON.parse(responseText);

        if (groupSettings.error) {
          Logger.log(`[ID-129] [ERROR API] No se pudo leer la configuración de ${groupEmail}: ${groupSettings.error.message}`);
          continue;
        }

        // Variable estricta a evaluar de la Groups Settings API
        const spamLevel = groupSettings.spamModerationLevel;

        // Evaluación de la postura de riesgo del recurso individual
        if (spamLevel === "ALLOW") {
          allowRiskCount++;
          affectedGroupsDetails.push(`${groupEmail} (ALLOW)`);
          Logger.log(`[DEBUG ID-129] Alerta: Grupo ${groupEmail} tiene la moderación de spam desactivada.`);
        } else if (spamLevel === "MODERATE" || spamLevel === "SILENTLY_MODERATE" || spamLevel === "REJECT") {
          protectedCount++;
        } else {
          // Captura de estados nulos o imprevistos de la API
          allowRiskCount++;
          affectedGroupsDetails.push(`${groupEmail} (Desconocido/Sin Filtro)`);
        }

      } catch (e) {
        Logger.log(`[ID-129] Excepción al procesar el endpoint de spam para ${groupEmail}: ${e.message}`);
      }
    }

    // Determinamos la postura global en función del peor caso encontrado
    const riesgoGlobal = (allowRiskCount > 0) ? "Alto" : "Bajo";

    // Mostramos directamente cuántos servicios/recursos están afectados en el valor principal
    const respuestaConcreta = `${allowRiskCount} inseguros de ${totalEvaluated} evaluados`;
    
    // Construcción del comentario descriptivo y analítico para el reporte
    let comentarioFinal = `Auditoría de políticas anti-spam Per-Group completada sobre ${totalEvaluated} recursos. `;
    if (allowRiskCount > 0) {
      comentarioFinal += `Se detectaron ${allowRiskCount} grupos configurados en modo ALLOW (Permitir todo el spam). Esto deshabilita el asalto algorítmico protector de Google Workspace y deposita correos/phishing masivos directamente en los buzones de los usuarios. Recursos comprometidos: ${affectedGroupsDetails.slice(0, 5).join(", ")}${affectedGroupsDetails.length > 5 ? '...' : ''}. Se recomienda forzar a MODERATE o SILENTLY_MODERATE para transferir el spam a una cola de revisión asíncrona.`;
    } else {
      comentarioFinal += `Excelente control perimetral. El 100% de los grupos individuales analizados (${protectedCount}) mitigan de forma activa las campañas de phishing al procesar el spam mediante colas de moderación (MODERATE/SILENTLY_MODERATE) o rechazo inmediato (REJECT).`;
    }

    Logger.log(`[LOG] Groups Spam Moderation Audit GLOBAL: Resultado -> ${respuestaConcreta} | Riesgo Máximo: ${riesgoGlobal}`);

    return {
      name: this.name,
      raw: { totalEvaluated, allowRiskCount, protectedCount },
      valorPrincipal: respuestaConcreta,
      comentario129: comentarioFinal,
      riesgo129: riesgoGlobal,
      score129: this.calcularScoreDeRiesgo(riesgoGlobal)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-129] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo129: "Medio", score129: 2, comentario129: msg };
  }
}