/**
 * Estrategia para auditar los Públicos Objetivo (Target Audiences) asignados.
 * Extrae la cantidad de audiencias y la configuración de grupos recomendados utilizando Admin SDK Directory API (v1).
 */
class DriveTargetAudiencesStrategy extends ApiStrategy {
  constructor(customerId, authService) {
    const configIDs = [
      { 
        id: "ID-100", 
        valueKey: "valorPrincipal",
        noteKey: "comentario100",
        riskKey: "riesgo100",
        scoreKey: "score100"
      }
    ];

    super("Drive Target Audiences Audit", configIDs);
    this.category = "Drive";
    this.customerId = customerId;
    this.authService = authService;
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return null;
  }

  evaluateInMemory(globalContext) {
    // ID-100 no depende de las políticas globales en memoria de Cloud Identity,
    // en su lugar hace una consulta en tiempo real a la Admin SDK Target Audiences API.
    
    let audiencesCount = 0;
    let jsonRaw = null;

    try {
      if (!this.authService) {
         throw new Error("Servicio de autenticación no suministrado en el constructor.");
      }

      const adminEmail = this.authService.getCurrentUserEmail(); 
      const authHeader = this.authService.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/admin.directory.targetaudiences.readonly"
      ]);

      // Intentamos primero v1.1 (endpoint documentado), con fallback a v1
      const endpoints = [
        `https://admin.googleapis.com/admin/directory/v1.1/customer/${this.customerId}/targetaudiences`,
        `https://admin.googleapis.com/admin/directory/v1/customer/${this.customerId}/targetaudiences`
      ];

      let lastError = null;
      for (const url of endpoints) {
        Logger.log(`[ID-100] [RED] Intentando endpoint: ${url}`);
        try {
          const response = UrlFetchApp.fetch(url, {
            method: "get",
            headers: { ...authHeader, "Cache-Control": "no-cache" },
            muteHttpExceptions: true
          });

          const code = response.getResponseCode();
          const contentType = response.getHeaders()["Content-Type"] || "";
          const body = response.getContentText();

          Logger.log(`[ID-100] [RED] HTTP ${code} | Content-Type: ${contentType} | Body (primeros 200 chars): ${body.substring(0, 200)}`);

          // Validar que la respuesta sea JSON antes de parsear
          if (!contentType.includes("application/json")) {
            Logger.log(`[ID-100] [WARN] Respuesta no-JSON detectada (${contentType}). Saltando este endpoint.`);
            lastError = `Endpoint ${url} devolvió ${contentType} en vez de JSON (HTTP ${code})`;
            continue;
          }

          if (code === 404) {
            Logger.log(`[ID-100] [WARN] Endpoint no encontrado (404). Intentando siguiente...`);
            lastError = `Endpoint ${url} no encontrado (HTTP 404)`;
            continue;
          }

          if (code !== 200) {
            lastError = `HTTP ${code}: ${body.substring(0, 200)}`;
            continue;
          }

          const json = JSON.parse(body);
          if (json.error) {
            lastError = `API Error: ${json.error.message || JSON.stringify(json.error)}`;
            continue;
          }

          // Éxito: extraer las audiencias
          const audiences = json.targetAudiences || [];
          audiencesCount = audiences.length;
          jsonRaw = audiences;
          lastError = null; // Limpiar errores previos
          break; // Salir del bucle de endpoints

        } catch (innerErr) {
          lastError = `${url}: ${innerErr.message}`;
          Logger.log(`[ID-100] [ERROR] Excepción en endpoint ${url}: ${innerErr.message}`);
        }
      }

      if (lastError && audiencesCount === 0 && jsonRaw === null) {
        Logger.log(`[ID-100] [WARN] Todos los endpoints fallaron. Último error: ${lastError}. Asumiendo 0 audiencias.`);
        // No lanzamos error: asumimos 0 audiencias si la API no es accesible
        // (comportamiento más seguro que mostrar ERROR en el reporte)
      }

    } catch (e) {
      Logger.log(`[ERROR] Drive Target Audiences Audit: ${e.message}`);
      return { 
        name: this.name, 
        raw: e.message,
        valorPrincipal: "ERROR",
        riesgo100: "Medio",
        score100: 2,
        comentario100: "Ocurrió un error al intentar consultar los públicos objetivo a través de Admin Directory API. " + e.message
      };
    }

    let respuestaConcreta;
    let riesgo100, comentario100;

    if (audiencesCount === 0) {
      respuestaConcreta = "0 Públicos Objetivo Configurados";
      riesgo100 = "Bajo";
      comentario100 = "No se encontraron públicos objetivo (Target Audiences) recomendados personalizados. Cuando los usuarios de la organización comparten archivos a nivel de toda la empresa con la opción para compartir vínculos predeterminada, esto minimiza las posibilidades de exposición masiva accidental asumiendo que las políticas restrictivas predominan por defecto.";
    } else if (audiencesCount <= 3) {
      respuestaConcreta = `${audiencesCount} Públicos Objetivo Configuradas`;
      riesgo100 = "Medio";
      comentario100 = "Se detectó el uso de públicos objetivo (Target Audiences). Es una práctica recomendada que permite a los usuarios compartir archivos con departamentos específicos en lugar de todos en el dominio, pero requiere revisión continua de que los grupos sean los apropiados y eviten una filtración horizontal de información.";
    } else {
      respuestaConcreta = `${audiencesCount} Públicos Objetivo Configuradas`;
      riesgo100 = "Alto";
      comentario100 = "Existen demasiadas opciones de públicos objetivo, esto puede provocar confusión en los usuarios que comparten enlaces e incrementar el riesgo de exposición accidental a departamentos equivocados al momento de configurar permisos a los recursos de Google Drive.";
    }

    Logger.log(`[LOG] Drive Target Audiences Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo100}`);

    return {
      name: this.name,
      raw: jsonRaw,
      valorPrincipal: respuestaConcreta,
      comentario100: comentario100,
      riesgo100: riesgo100,
      score100: this.calcularScoreDeRiesgo(riesgo100)
    };
  }
}
