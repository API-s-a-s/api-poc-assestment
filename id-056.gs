/**
 * Estrategia para auditar las aplicaciones de terceros que han accedido a los datos de Google.
 * Evalúa y lista las aplicaciones autorizadas mediante tokens OAuth por los usuarios.
 * Ignora las políticas y usa AdminDirectory.Tokens para traer la información real.
 */
class AccessedAppsStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-056", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario056",
        riskKey: "riesgo056",
        scoreKey: "score056"
      }
    ];

    super("Accessed Third Party Apps Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Integración de aplicaciones";
  }

  evaluateInMemory(globalContext) {
    const { census } = globalContext;

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo no encontrado en memoria).");
    }
    let uniqueApps = new Map();
    let errorOccurred = false;
    let errorMsg = "";

    try {
      for (const user of census) {
        let pageToken = null;
        do {
          const response = AdminDirectory.Tokens.list(user.id || user.email, {
            maxResults: 100,
            pageToken: pageToken
          });

          if (response.items && response.items.length > 0) {
            response.items.forEach(token => {
              // Filtrar tokens anónimos o no relevantes si es necesario
              const clientId = token.clientId;
              const appName = token.displayText || "Aplicación Desconocida";
              
              // Filtro heurístico para ignorar apps propiedad de Google
              const isGoogleApp = appName.toLowerCase().includes("google") ||
                                  appName.toLowerCase().includes("apps script") ||
                                  appName.toLowerCase() === "chrome" ||
                                  appName.toLowerCase().includes("android") ||
                                  appName.toLowerCase().includes("ios");
              
              if (clientId && !uniqueApps.has(clientId) && !isGoogleApp) {
                uniqueApps.set(clientId, appName);
              }
            });
          }
          
          pageToken = response.nextPageToken;
        } while (pageToken);
      }
    } catch (e) {
      errorOccurred = true;
      errorMsg = e.message;
      Logger.log(`[ID-056] Error al listar tokens: ${e.message}`);
    }

    if (errorOccurred && uniqueApps.size === 0) {
       return this._buildErrorResponse(`Error al obtener tokens de AdminDirectory: ${errorMsg}`);
    }

    const appsCount = uniqueApps.size;
    const appsList = Array.from(uniqueApps.values());

    Logger.log(`[ID-056] Total de aplicaciones únicas que han accedido: ${appsCount}`);

    let riesgo056, comentario056;

    if (appsCount === 0) {
      riesgo056 = "Bajo";
      comentario056 = "No se han detectado aplicaciones de terceros que hayan accedido a los datos de Google Workspace en el dominio.";
    } else if (appsCount <= 5) {
      riesgo056 = "Medio";
      comentario056 = `${appsList.join(", ")}. `;
    } else {
      riesgo056 = "Alto";
      comentario056 = `${appsList.join(", ")}.`;
    }

    return {
      name: this.name,
      valorPrincipal: `${appsCount} apps`,
      comentario056: comentario056,
      riesgo056: riesgo056,
      score056: this.calcularScoreDeRiesgo(riesgo056)
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

  _buildErrorResponse(msg) {
    Logger.log(`[ID-056] ERROR: ${msg}`);
    return { 
      name: this.name, 
      valorPrincipal: "ERROR", 
      riesgo056: "Medio", 
      score056: 2, 
      comentario056: msg 
    };
  }
}
