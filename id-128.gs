/**
 * Estrategia para auditar los permisos de acceso y visibilidad de recursos individuales de Google Groups.
 * Evalúa los parámetros whoCanJoin y whoCanViewGroup de forma granular por recurso.
 * Utiliza Google Groups Settings API (v1).
 * Endpoint: https://www.googleapis.com/groups/v1/groups/{groupUniqueId}?alt=json
 */
class GroupsSettingsAccessStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-128", 
        valueKey: "valorPrincipal",
        noteKey: "comentario128",
        riskKey: "riesgo128",
        scoreKey: "score128"
      }
    ];

    super("Groups Individual Resource Access Settings Audit", configIDs);
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

    Logger.log(`[ID-128] [FALLBACK] Contexto vacío. Consultando grupos vía AdminDirectory SDK...`);
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
        Logger.log(`[ID-128] [FALLBACK SUCCESS] Se encontraron ${groupsList.length} grupos.`);
      }
    } catch (e) {
      Logger.log(`[ID-128] [FALLBACK ERROR] Error al consultar AdminDirectory SDK: ${e.message}`);
    }
    return groupsList;
  }

  evaluateInMemory(globalContext) {
    const { auth } = globalContext;
    if (!auth) return this._buildErrorResponse("Falta el objeto de autenticación ('auth') en el contexto global.");

    const groupsList = this._getGroupsList(globalContext);
    Logger.log(`[DEBUG ID-128] Total de grupos detectados para evaluar: ${groupsList.length}`);

    if (groupsList.length === 0) {
      Logger.log(`[ID-128] [WARNING] No se encontraron grupos en el dominio.`);
      return {
        name: this.name,
        raw: null,
        valorPrincipal: "Sin grupos detectados",
        comentario128: "No se encontraron grupos configurados en el dominio para auditar sus permisos de acceso.",
        riesgo128: "Bajo",
        score128: 3
      };
    }

    let totalEvaluated = 0;
    let highRiskCount = 0;
    let mediumRiskCount = 0;
    let lowRiskCount = 0;
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
      try {
        // Se agrega ?alt=json para forzar la respuesta en formato JSON
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
        const groupSettings = JSON.parse(response.getContentText());

        if (groupSettings.error) {
          Logger.log(`[ID-128] [ERROR API] ${groupEmail}: ${groupSettings.error.message}`);
          continue;
        }

        const whoCanJoin = groupSettings.whoCanJoin;
        const whoCanViewGroup = groupSettings.whoCanViewGroup;

        if (whoCanViewGroup === "ANYONE_CAN_VIEW" || whoCanJoin === "ANYONE_CAN_JOIN") {
          highRiskCount++;
          affectedGroupsDetails.push(`${groupEmail} (Público)`);
        } else if (whoCanViewGroup === "ALL_IN_DOMAIN_CAN_VIEW" || whoCanViewGroup === "ALL_YOUR_ORGANIZATION_MEMBERS") {
          mediumRiskCount++;
          affectedGroupsDetails.push(`${groupEmail} (Abierto al dominio)`);
        } else {
          lowRiskCount++;
        }

      } catch (e) {
        Logger.log(`[ID-128] Excepción al procesar ${groupEmail}: ${e.message}`);
      }
    }

    let riesgoGlobal = "Bajo";
    if (highRiskCount > 0) riesgoGlobal = "Alto";
    else if (mediumRiskCount > 0) riesgoGlobal = "Medio";

    const totalVulnerables = highRiskCount + mediumRiskCount;
    const respuestaConcreta = totalVulnerables > 0 
      ? `${totalVulnerables} de ${totalEvaluated} grupos desprotegidos` 
      : `0 de ${totalEvaluated} grupos desprotegidos`;
    
    let comentarioFinal = "";
    if (totalVulnerables > 0) {
      comentarioFinal = `Se analizaron ${totalEvaluated} grupos. Se detectaron ${highRiskCount} grupos públicos y ${mediumRiskCount} visibles para toda la organización. Grupos afectados: ${affectedGroupsDetails.slice(0, 5).join(", ")}.`;
    } else {
      comentarioFinal = `Se analizaron ${totalEvaluated} grupos. Todos mantienen el acceso y la visibilidad restringidos únicamente a sus miembros.`;
    }

    return {
      name: this.name,
      raw: { totalEvaluated, highRiskCount, mediumRiskCount, lowRiskCount },
      valorPrincipal: respuestaConcreta,
      comentario128: comentarioFinal,
      riesgo128: riesgoGlobal,
      score128: this.calcularScoreDeRiesgo(riesgoGlobal)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo128: "Medio", score128: 2, comentario128: msg };
  }
}