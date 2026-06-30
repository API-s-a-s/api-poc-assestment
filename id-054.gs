/**
 * Estrategia para auditar eventos de instalación de aplicaciones de administrador.
 * Busca eventos relacionados con instalación y delegación en los registros de auditoría.
 * Utiliza Admin SDK Reports API
 * Contiene la lógica de negocio basada en toadd.csv para ID-054
 */
class AdminAppInstallEventStrategy extends ApiStrategy {
  constructor() { 
    const configIDs = [
      { 
        id: "ID-054", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario054",
        riskKey: "riesgo054",
        scoreKey: "score054"
      }
    ];

    super("Admin App Install Events Audit", configIDs);
    this.url = `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin`;
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
        riesgo054: "Medio",
        score054: 2,
        comentario054: "Error de lectura, conectividad o permisos insuficientes en la API Reports que impide consultar los registros de actividad administrativa y contabilizar los eventos de instalación."
      };
    }

    let installEventsCount = 0;
    let hasDangerousScopes = false;
    let dangerousApps = new Set();

    if (json.items && json.items.length > 0) {
      json.items.forEach(item => {
        if (item.events) {
          item.events.forEach(event => {
            const eventName = (event.name || "").toUpperCase();
            
            if (eventName.includes("INSTALL") || 
                eventName.includes("MARKETPLACE") || 
                eventName === "AUTHORIZE_API_CLIENT_ACCESS") {
              installEventsCount++;
              
              if (event.parameters) {
                const logStr = JSON.stringify(event.parameters).toLowerCase();
                if (logStr.includes('drive') || logStr.includes('gmail') || logStr.includes('mail.google.com')) {
                    hasDangerousScopes = true;
                    const appParam = event.parameters.find(p => p.name === 'APPLICATION_NAME' || p.name === 'CLIENT_ID');
                    if (appParam) dangerousApps.add(appParam.value);
                }
              }
            }
          });
        }
      });
    }

    let riesgo054, comentario054;

    if (installEventsCount === 0) {
      riesgo054 = "Bajo";
      comentario054 = "La bitácora de auditoría no registra eventos recientes de instalación de aplicaciones del Marketplace ni autorizaciones de acceso a clientes API ejecutadas por un administrador en el dominio.";
    } else {
      if (hasDangerousScopes) {
         riesgo054 = "Alto";
         const appsArray = Array.from(dangerousApps);
         const appsStr = appsArray.length > 0 ? ` (Apps: ${appsArray.join(", ")})` : "";
         comentario054 = `Se registraron ${installEventsCount} instalaciones/autorizaciones recientes. ATENCIÓN: Se detectaron instalaciones con permisos de alto riesgo (Drive y/o Gmail)${appsStr}.`;
      } else {
         riesgo054 = "Medio";
         comentario054 = `Se registraron ${installEventsCount} eventos recientes de instalaciones de Marketplace o autorizaciones de acceso API por un administrador.`;
      }
    }

    return {
      name: this.name,
      raw: json,
      valorPrincipal: installEventsCount,
      comentario054: comentario054,
      riesgo054: riesgo054,
      score054: this.calcularScoreDeRiesgo(riesgo054)
    };
  }
}