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

    Logger.log(`[DEBUG ID-100] Iniciando DriveTargetAudiencesStrategy.evaluateInMemory...`);

    try {
      if (!this.authService) {
         throw new Error("Servicio de autenticación no suministrado en el constructor.");
      }

      const adminEmail = this.authService.getCurrentUserEmail(); 
      Logger.log(`[DEBUG ID-100] Generando token de acceso privilegiado para: ${adminEmail}`);
      const authHeader = this.authService.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/admin.directory.group.readonly"
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
          const contentType = response.getHeaders()["Content-Type"] || response.getHeaders()["content-type"] || "";
          const body = response.getContentText();

          Logger.log(`[ID-100] [RED] HTTP ${code} | Content-Type: ${contentType} | Longitud Body: ${body ? body.length : 0} bytes`);

          // Validar que la respuesta sea JSON antes de parsear
          if (!contentType.toLowerCase().includes("application/json")) {
            Logger.log(`[ID-100] [WARN] Respuesta no-JSON detectada (${contentType}). Saltando este endpoint. Body parcial: ${body.substring(0, 300)}`);
            lastError = `Endpoint ${url} devolvió ${contentType} en vez de JSON (HTTP ${code})`;
            continue;
          }

          if (code === 404) {
            Logger.log(`[ID-100] [WARN] Endpoint no encontrado (404). Intentando siguiente...`);
            lastError = `Endpoint ${url} no encontrado (HTTP 404)`;
            continue;
          }

          if (code !== 200) {
            Logger.log(`[ID-100] [WARN] Código de respuesta no esperado: HTTP ${code}. Body: ${body.substring(0, 500)}`);
            lastError = `HTTP ${code}: ${body.substring(0, 200)}`;
            continue;
          }

          const json = JSON.parse(body);
          if (json.error) {
            Logger.log(`[ID-100] [ERROR] Error devuelto por la API de Google: ${JSON.stringify(json.error)}`);
            lastError = `API Error: ${json.error.message || JSON.stringify(json.error)}`;
            continue;
          }

          // Éxito: extraer las audiencias
          const audiences = json.targetAudiences || [];
          audiencesCount = audiences.length;
          jsonRaw = audiences;
          lastError = null; // Limpiar errores previos

          Logger.log(`[DEBUG ID-100] Conexión exitosa a la API. Se obtuvieron ${audiencesCount} públicos objetivo.`);
          audiences.forEach((aud, index) => {
            Logger.log(`[DEBUG ID-100] Audiencia #${index + 1}: ID=${aud.name || 'N/A'} | DisplayName="${aud.displayName || 'N/A'}" | Description="${aud.description || 'N/A'}"`);
          });

          break; // Salir del bucle de endpoints

        } catch (innerErr) {
          lastError = `${url}: ${innerErr.message}`;
          Logger.log(`[ID-100] [ERROR] Excepción en endpoint ${url}: ${innerErr.message}`);
        }
      }

      if (lastError && audiencesCount === 0 && jsonRaw === null) {
        Logger.log(`[ID-100] [WARN] Todos los endpoints fallaron. Último error registrado: ${lastError}. Asumiendo 0 audiencias en el reporte.`);
      }

    } catch (e) {
      Logger.log(`[ERROR] Drive Target Audiences Audit (Excepción Crítica): ${e.message}`);
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
      comentario100 = "No se encontraron públicos objetivo recomendados personalizados, esto minimiza la exposición asumiendo que las políticas restrictivas predominan por defecto.";
    } else if (audiencesCount <= 3) {
      respuestaConcreta = `${audiencesCount} Públicos Objetivo Configuradas`;
      riesgo100 = "Medio";
      comentario100 = "Se detectó el uso de públicos objetivo.";
    } else {
      respuestaConcreta = `${audiencesCount} Públicos Objetivo Configuradas`;
      riesgo100 = "Alto";
      comentario100 = "Existen demasiadas opciones de públicos objetivo,.";
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
