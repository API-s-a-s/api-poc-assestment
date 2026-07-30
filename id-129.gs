/**
 * Estrategia para auditar los niveles de moderación de spam en recursos individuales de Google Groups.
 * Evalúa el parámetro spamModerationLevel de forma granular por recurso.
 * Utiliza Google Groups Settings API (v1).
 * Endpoint: https://www.googleapis.com/groups/v1/groups/{groupUniqueId}?alt=json
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

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  _getGroupsList(globalContext) {
    let groupsList = globalContext.groups || globalContext.allGroups || [];
    if (groupsList.length > 0) return groupsList;

    Logger.log(`[ID-129] [FALLBACK] Contexto vacío. Consultando grupos vía AdminDirectory SDK...`);
    try {
      if (typeof AdminDirectory !== 'undefined' && AdminDirectory.Groups) {
        let pageToken = null;
        do {
          const response = AdminDirectory.Groups.list({
            customer: this.customerId || "my_customer",
            maxResults: 200,
            pageToken: pageToken
          });
          if (response.groups) {
            groupsList.push(...response.groups);
          }
          pageToken = response.nextPageToken;
        } while (pageToken);
        Logger.log(`[ID-129] [FALLBACK SUCCESS] Se encontraron ${groupsList.length} grupos.`);
      }
    } catch (e) {
      Logger.log(`[ID-129] [FALLBACK ERROR] Error al consultar AdminDirectory SDK: ${e.message}`);
    }
    return groupsList;
  }

  evaluateInMemory(globalContext) {
    const { auth } = globalContext;
    if (!auth) return this._buildErrorResponse("Falta el objeto de autenticación ('auth') en el contexto global.");

    const groupsList = this._getGroupsList(globalContext);
    
    Logger.log(`[DEBUG ID-129] ==================================================`);
    Logger.log(`[DEBUG ID-129] Total de grupos detectados para evaluar: ${groupsList.length}`);

    if (groupsList.length === 0) {
      Logger.log(`[ID-129] [WARNING] No se encontraron grupos en el dominio.`);
      return {
        name: this.name,
        raw: null,
        valorPrincipal: "Sin grupos detectados",
        comentario129: "No se encontraron grupos configurados en el dominio para auditar la moderación de spam.",
        riesgo129: "Bajo",
        score129: 3
      };
    }

    let totalEvaluated = 0;
    let allowRiskCount = 0;
    let protectedCount = 0;
    let affectedGroupsDetails = [];

    const adminEmail = auth.getCurrentUserEmail(); 
    const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
      "https://www.googleapis.com/auth/apps.groups.settings"
    ]);

    for (let i = 0; i < groupsList.length; i++) {
      const groupItem = groupsList[i];
      const groupEmail = (typeof groupItem === 'object') ? (groupItem.email || groupItem.id) : groupItem;
      
      if (!groupEmail) continue;

      totalEvaluated++;
      Logger.log(`\n[DEBUG ID-129] [GRUPO ${totalEvaluated}/${groupsList.length}] Evaluando correo: ${groupEmail}`);

      try {
        const url = `https://www.googleapis.com/groups/v1/groups/${encodeURIComponent(groupEmail)}?alt=json`;
        const options = {
          method: "get",
          headers: { 
            ...privilegedHeader, 
            "Accept": "application/json",
            "Cache-Control": "no-cache" 
          },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const statusCode = response.getResponseCode();
        const responseText = response.getContentText();

        Logger.log(`[DEBUG ID-129] HTTP Status (${groupEmail}): ${statusCode}`);
        Logger.log(`[DEBUG ID-129] RAW Response Body (${groupEmail}): ${responseText}`);

        const groupSettings = JSON.parse(responseText);

        if (groupSettings.error) {
          Logger.log(`[ID-129] [ERROR API] ${groupEmail}: ${groupSettings.error.message}`);
          continue;
        }

        const spamLevel = groupSettings.spamModerationLevel;
        Logger.log(`[DEBUG ID-129] Valor extraído 'spamModerationLevel' para ${groupEmail}: '${spamLevel}'`);

        if (spamLevel === "ALLOW") {
          allowRiskCount++;
          affectedGroupsDetails.push(`${groupEmail} (ALLOW)`);
          Logger.log(`[DEBUG ID-129] -> Dictamen individual: RIESGO ALTO (ALLOW)`);
        } else if (spamLevel === "MODERATE" || spamLevel === "SILENTLY_MODERATE" || spamLevel === "REJECT") {
          protectedCount++;
          Logger.log(`[DEBUG ID-129] -> Dictamen individual: PROTEGIDO (${spamLevel})`);
        } else {
          allowRiskCount++;
          affectedGroupsDetails.push(`${groupEmail} (Desconocido: ${spamLevel})`);
          Logger.log(`[DEBUG ID-129] -> Dictamen individual: VALOR NO RECONOCIDO (${spamLevel})`);
        }

      } catch (e) {
        Logger.log(`[ID-129] Excepción crítica al procesar ${groupEmail}: ${e.message}`);
      }
    }

    Logger.log(`\n[DEBUG ID-129] Resumen final: Evaluados=${totalEvaluated} | Inseguros=${allowRiskCount} | Protegidos=${protectedCount}`);

    const riesgoGlobal = (allowRiskCount > 0) ? "Alto" : "Bajo";
    
    // Valor principal simplificado y directo para la celda
    const respuestaConcreta = `${allowRiskCount} inseguros con estado permitido (${protectedCount} moderados/rechazados)`;
    
    // Comentario explicativo enriquecido
    let comentarioFinal = "";
    if (allowRiskCount > 0) {
      comentarioFinal = `Se analizaron ${totalEvaluated} grupos: ${allowRiskCount} inseguros con estado permitido (ALLOW) sin filtro de spam y ${protectedCount} moderados o rechazados. Grupos afectados: ${affectedGroupsDetails.slice(0, 5).join(", ")}.`;
    } else {
      comentarioFinal = `Se analizaron ${totalEvaluated} grupos: 0 inseguros con estado permitido y ${protectedCount} moderados o rechazados (con filtro de spam activo).`;
    }

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
    return { name: this.name, valorPrincipal: "ERROR", riesgo129: "Medio", score129: 2, comentario129: msg };
  }
}