/**
 * Orquestador (Facade) para la ejecución de estrategias de auditoría.
 * Referencia Arquitectónica: Patrón de diseño Facade (https://refactoring.guru/es/design-patterns/facade)
 */
class SecurityAuditorFacade {
  constructor(authService, globalContext = null, errorCollector = null) {
    this.auth = authService;
    this.globalContext = globalContext; 
    this.strategies = [];
    this.errorCollector = errorCollector;
  }

  addStrategy(strategy) {
    this.strategies.push(strategy);
  }

  ejecutarTodo() {
    const resultados = [];
    const authHeader = this.auth.getAuthHeader();

    for (let i = 0; i < this.strategies.length; i++) {
      const s = this.strategies[i];

      try {
        let parsedRes;

        // Inyección universal de authHeader: permite que estrategias híbridas
        // (evaluateInMemory con fallback de red) puedan usar fetchWithBackoff/fetchPaginated.
        if (typeof s.setAuthHeader === 'function') {
          s.setAuthHeader(authHeader);
        }

        if (typeof s.evaluateInMemory === 'function') {
          Logger.log(`[FACADE] Ejecutando estrategia en memoria: ${s.name}`);
          parsedRes = s.evaluateInMemory(this.globalContext);
        } else {
          Logger.log(`[FACADE] Ejecutando estrategia por red: ${s.name}`);
          const config = s.getRequestConfig();
          config.headers = {
            ...(config.headers || {}),
            ...authHeader,
            "Cache-Control": "no-cache, no-store, max-age=0, must-revalidate",
            "Pragma": "no-cache"
          };

          config.url += (config.url.includes("?") ? "&" : "?") + "t=" + new Date().getTime();
          // La llamada de red se delega a fetchWithBackoff internamente en la estrategia,
          // o se asume manejada si el endpoint es estable.
          const response = UrlFetchApp.fetch(config.url, config);
          const json = JSON.parse(response.getContentText());
          parsedRes = s.parseResponse(json);      
          // ahora es responsabilidad exclusiva del adaptador de Exponential Backoff.
        }

        // Inspección y registro en el colector de errores si está activo
        if (this.errorCollector) {
          if (!parsedRes) {
            this.errorCollector.add(s.name, "EMPTY_RESPONSE", "La estrategia retornó un resultado nulo o vacío.");
          } else {
            const val = (parsedRes.valorPrincipal !== undefined && parsedRes.valorPrincipal !== null)
              ? parsedRes.valorPrincipal.toString()
              : "";
            if (val.toUpperCase().includes("ERROR")) {
              // Buscar comentarios de detalle asociados al error
              let detalleError = val;
              for (const key of Object.keys(parsedRes)) {
                if (key.startsWith("comentario") && parsedRes[key]) {
                  detalleError = parsedRes[key];
                  break;
                }
              }
              this.errorCollector.add(s.name, "API_ERROR", detalleError);
            }
          }
        }

        resultados.push(parsedRes);

      } catch (e) {
        Logger.log(`Error en ${s.name}: ${e.message}`);
        if (this.errorCollector) {
          this.errorCollector.add(s.name, "EXCEPTION", e.stack || e.message);
        }
      }      
    }

    // Imprimimos el log unificado de licencias antes de retornar los resultados
    if (typeof CELParserEngine !== 'undefined') {
       CELParserEngine.printDiscardedLogs();
    }
    return resultados;
  }
}
