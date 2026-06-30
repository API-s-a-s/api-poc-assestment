/**
 * Estrategia para auditar el uso de Domain-Wide Delegation (DWD).
 * Busca eventos de 'allow_token_request' en los registros de auditoría.
 * Utiliza Admin SDK Reports API
 */
class DwdTokenRequestAuditStrategy extends ApiStrategy {
  constructor() { 
    const configIDs = [
      { 
        id: "ID-049", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario049",
        riskKey: "riesgo049",
        scoreKey: "score049"
      }
    ];

    super("DWD Token Request Audit", configIDs);
    this.url = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/access_evaluation?eventName=allow_token_request`;
    this.category = "Integración de aplicaciones";
  }

  getRequestConfig() {
    return {
      url: this.url,
      method: "get",
      muteHttpExceptions: true
    };
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  parseResponse(json) {
    if (json.error) {
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo049: "Medio",
        score049: 2,
        comentario049: "Error de lectura, conectividad o permisos insuficientes en la API Reports que impide consultar los registros de actividad y contabilizar los eventos de delegación de dominio."
      };
    }

    let dwdEventCount = 0;
    let totalEventsCount = 0;
    let hasDangerousScopes = false;
    let dangerousClients = new Set();
    let dwdEventsList = [];

    if (json.items && json.items.length > 0) {
      json.items.forEach(item => {
        if (item.events) {
          item.events.forEach(event => {
            totalEventsCount++;
            if (event.parameters) {
              const configSource = event.parameters.find(p => p.name === 'configuration_source');
              if (configSource && configSource.value === 'DOMAIN_WIDE_DELEGATION') {
                dwdEventCount++;
                dwdEventsList.push(event);
                
                const logStr = JSON.stringify(event.parameters).toLowerCase();
                if (logStr.includes('drive') || logStr.includes('gmail') || logStr.includes('mail.google.com')) {
                    hasDangerousScopes = true;
                    const clientParam = event.parameters.find(p => p.name === 'client_id' || p.name === 'app_name');
                    if (clientParam) dangerousClients.add(clientParam.value);
                }
              }
            }
          });
        }
      });
    }

    let riesgo049, comentario049;
    let rawOutput = JSON.stringify(dwdEventsList);

    if (dwdEventCount === 0) {
      riesgo049 = "Bajo";
      rawOutput = "0";
      comentario049 = `${dwdEventCount} de ${totalEventsCount} peticiones DWD: La bitácora no registra eventos de delegación de dominio.`;
    } else {
      if (hasDangerousScopes) {
        riesgo049 = "Alto";
        const clientsArray = Array.from(dangerousClients);
        const clientsStr = clientsArray.length > 0 ? ` (Clientes: ${clientsArray.join(", ")})` : "";
        comentario049 = `${dwdEventCount} de ${totalEventsCount} peticiones DWD: Se identificaron peticiones con permisos de alto riesgo (Drive, Gmail)${clientsStr}.`;
      } else {
        riesgo049 = "Medio";
        comentario049 = `${dwdEventCount} de ${totalEventsCount} peticiones DWD: No se observaron permisos críticos (Drive/Gmail) en los logs, pero se sugiere revisar las aplicaciones autorizadas.`;
      }
    }

    return {
      name: this.name,
      raw: json,
      valorPrincipal: rawOutput, 
      comentario049: comentario049,
      riesgo049: riesgo049,
      score049: this.calcularScoreDeRiesgo(riesgo049)
    };
  }
}