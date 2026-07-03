/**
 * Estrategia para auditar los permisos de acceso y visibilidad de recursos individuales de Google Groups.
 * Evalúa los parámetros whoCanJoin y whoCanViewGroup de forma granular por recurso.
 * Utiliza Google Groups Settings API (v1).
 * Endpoint: https://www.googleapis.com/groups/v1/groups/{groupUniqueId}
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
    // Buscamos los grupos en el contexto global (soportando variantes de nomenclatura del core)
    const groupsList = globalContext.groups || globalContext.allGroups || [];
    
    Logger.log(`[DEBUG ID-128] Total de grupos detectados en el contexto para evaluar: ${groupsList.length}`);

    if (!auth) return this._buildErrorResponse("Falta el objeto de autenticación ('auth') en el contexto global.");
    if (groupsList.length === 0) {
      Logger.log(`[ID-128] [WARNING] No se encontraron grupos para evaluar en el contexto global. Asegúrate de que el Core los cargue previamente.`);
      return {
        name: this.name,
        raw: null,
        valorPrincipal: "Sin grupos detectados",
        comentario128: "No se procesaron grupos debido a que la lista en el contexto global se encuentra vacía.",
        riesgo128: "Bajo",
        score128: 3
      };
    }

    // Contadores para medir el impacto ("cuántos servicios están afectados")
    let totalEvaluated = 0;
    let highRiskCount = 0;
    let mediumRiskCount = 0;
    let lowRiskCount = 0;
    let affectedGroupsDetails = [];

    // Obtenemos credenciales una sola vez para optimizar el bucle
    const adminEmail = auth.getCurrentUserEmail(); 
    const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
      "https://www.googleapis.com/auth/apps.groups.settings"
    ]);

    // Iteramos sobre cada grupo de manera granular
    for (let i = 0; i < groupsList.length; i++) {
      // Soportamos si el elemento es un String (email) o un Objeto con propiedad email
      const groupItem = groupsList[i];
      const groupEmail = (typeof groupItem === 'object') ? (groupItem.email || groupItem.id) : groupItem;
      
      if (!groupEmail) {
        Logger.log(`[DEBUG ID-128] Registro de grupo inválido en índice ${i}: ${JSON.stringify(groupItem)}`);
        continue;
      }

      totalEvaluated++;
      Logger.log(`[ID-128] [PROCESANDO ${totalEvaluated}/${groupsList.length}] Evaluando configuración del grupo: ${groupEmail}`);

      try {
        const url = `https://www.googleapis.com/groups/v1/groups/${encodeURIComponent(groupEmail)}`;
        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const responseText = response.getContentText();
        
        // LOG EXPLICITO EXIGIDO: Imprimir exactamente qué llega de la API de Google por cada recurso
        Logger.log(`[DEBUG ID-128] [RAW RESPONSE] Grupo: ${groupEmail} -> ${responseText}`);

        const groupSettings = JSON.parse(responseText);

        if (groupSettings.error) {
          Logger.log(`[ID-128] [ERROR API] No se pudo obtener la configuración de ${groupEmail}: ${groupSettings.error.message}`);
          continue;
        }

        // Variables estrictas del recurso individual
        const whoCanJoin = groupSettings.whoCanJoin;
        const whoCanViewGroup = groupSettings.whoCanViewGroup;

        // Evaluación de la matriz de riesgo del recurso individual
        let currentGroupRisk = "Bajo";

        if (whoCanViewGroup === "ANYONE_CAN_VIEW" || whoCanJoin === "ANYONE_CAN_JOIN") {
          currentGroupRisk = "Alto";
          highRiskCount++;
          affectedGroupsDetails.push(`${groupEmail} (Público)`);
        } else if (whoCanViewGroup === "ALL_IN_DOMAIN_CAN_VIEW" || whoCanViewGroup === "ALL_YOUR_ORGANIZATION_MEMBERS") {
          currentGroupRisk = "Medio";
          mediumRiskCount++;
          affectedGroupsDetails.push(`${groupEmail} (Abierto al Dominio)`);
        } else {
          lowRiskCount++;
        }

        Logger.log(`[DEBUG ID-128] Grupo: ${groupEmail} | whoCanJoin: ${whoCanJoin} | whoCanViewGroup: ${whoCanViewGroup} | Riesgo: ${currentGroupRisk}`);

      } catch (e) {
        Logger.log(`[ID-128] Excepción crítica al procesar el grupo ${groupEmail}: ${e.message}`);
      }
    }

    // Determinamos la postura global basada en el peor escenario encontrado
    let riesgoGlobal = "Bajo";
    if (highRiskCount > 0) riesgoGlobal = "Alto";
    else if (mediumRiskCount > 0) riesgoGlobal = "Medio";

    // Formateamos la respuesta concreta mostrando cuántos recursos (servicios) están afectados
    const respuestaConcreta = `${highRiskCount} Alto / ${mediumRiskCount} Medio de ${totalEvaluated} evaluados`;
    
    // Construimos el comentario dinámico con los hallazgos exactos
    let comentarioFinal = `Auditoría Per-Group completada sobre ${totalEvaluated} grupos instanciados. `;
    if (highRiskCount > 0 || mediumRiskCount > 0) {
      comentarioFinal += `Se detectaron fallas de aislamiento de recursos. Grupos en riesgo ALTO (Acceso/Visibilidad Pública): ${highRiskCount}. Grupos en riesgo MEDIO (Visibilidad abierta a todo el dominio): ${mediumRiskCount}. Recursos afectados: ${affectedGroupsDetails.slice(0, 5).join(", ")}${affectedGroupsDetails.length > 5 ? '...' : ''}. Esto viola las directrices de menor privilegio exponiendo comunicaciones internas.`;
    } else {
      comentarioFinal += "Todos los grupos individuales evaluados cumplen con las políticas estrictas de privacidad (Acceso restringido solo a miembros o invitados autorizados).";
    }

    Logger.log(`[LOG] Groups Settings Access Audit GLOBAL: Resultado -> ${respuestaConcreta} | Riesgo Máximo: ${riesgoGlobal}`);

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
    Logger.log(`[ID-128] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo128: "Medio", score128: 2, comentario128: msg };
  }
}