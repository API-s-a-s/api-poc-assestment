/**
 * Estrategia para auditar alertas de seguridad (Phishing, Accesos Anómalos).
 * Utiliza la Google Workspace Alert Center API.
 * NOTA: Estrategia de red (Requiere añadir el scope 'apps.alerts' en appsscript.json).
 */
class SecurityAlertsAuditStrategy extends ApiStrategy {
  constructor() {
    const configIDs = [
      { 
        id: "ID-032", 
        valueKey: "valorPrincipal", // Entregará el total de alertas (entero)
        noteKey: "comentario032",
        riskKey: "riesgo032",
        scoreKey: "score032"
      }
    ];

    super("Security Alerts & Threat Visibility Audit", configIDs);
    
    // Endpoint oficial y de producción para consultar las alertas (NUNCA cambiar a v1)
    this.url = "https://alertcenter.googleapis.com/v1beta1/alerts";
    this.category = "Identidad y autenticación";
  }

  getRequestConfig() {
    return {
      url: this.url,
      method: "get",
      muteHttpExceptions: true
    };
  }

  parseResponse(json) {
    // =======================================================================
    // PASO 1: EVALUACIÓN DE ERRORES PRINCIPALES
    // =======================================================================
    if (json.error) {
      Logger.log(`[ID-032] ERROR CRÍTICO Alert Center API: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR API", 
        riesgo032: "Medio",
        score032: 2,
        comentario032: "Permisos insuficientes."
      };
    }

    // =======================================================================
    // PASO 2: PAGINACIÓN MASIVA DE ALERTAS
    // Evita puntos ciegos si la organización tiene un historial largo de incidentes.
    // =======================================================================
    let alertas = json.alerts || [];

    if (json.nextPageToken) {
      Logger.log("[ID-032] Paginación detectada. Extrayendo historial completo de alertas...");
      const todasLasAlertas = this.fetchPaginated(this.url, "alerts");
      if (todasLasAlertas) alertas = todasLasAlertas;
    }

    const totalAlertas = alertas.length;

    // =======================================================================
    // PASO 3: ANÁLISIS FORENSE DE INCIDENTES
    // Clasificamos las alertas para dar un contexto exacto al auditor.
    // =======================================================================
    let phishing = 0;
    let anomalos = 0;
    let otros = 0;

    for (const alerta of alertas) {
      const tipo = (alerta.type || "").toLowerCase();
      if (tipo.includes('phishing')) {
        phishing++;
      } else if (tipo.includes('login') || tipo.includes('suspicious')) {
        anomalos++;
      } else {
        otros++;
      }
    }

    // =======================================================================
    // PASO 4: ASIGNAR RIESGO Y CONSTRUIR RESULTADO
    // =======================================================================
    let riesgo032, comentario032;

    if (totalAlertas > 0) {
      riesgo032 = "Medio";
      comentario032 = `El centro de alertas documenta ${totalAlertas} incidentes.`;
    } else {
      riesgo032 = "Bajo";
      comentario032 = "El centro de alertas no reporta incidentes activos de seguridad.";
    }

    Logger.log(`[ID-032] Métrica procesada. Total alertas: ${totalAlertas} | Riesgo: ${riesgo032}`);

    return {
      name: this.name,
      // Retornamos un resumen en raw en lugar de todo el JSON para no saturar las celdas de Sheets
      raw: { totalAlertas, desglose: { phishing, anomalos, otros } },
      valorPrincipal: `${totalAlertas} Alertas`,
      comentario032: comentario032,
      riesgo032: riesgo032,
      score032: this.calcularScoreDeRiesgo(riesgo032)
    };
  }

  // Traductor de texto a número (Score)
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return "";
  }
}