/**
 * Orquestador (Facade) para la ejecución de estrategias de auditoría.
 * Referencia Arquitectónica: Patrón de diseño Facade (https://refactoring.guru/es/design-patterns/facade)
 */
class SecurityAuditorFacade {
  constructor(authService, globalContext = null) {
    this.auth = authService;
    this.globalContext = globalContext; 
    this.strategies = [];
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

          if (typeof s.setAuthHeader === 'function') {
            s.setAuthHeader(config.headers);
          }
          config.url += (config.url.includes("?") ? "&" : "?") + "t=" + new Date().getTime();
          // La llamada de red se delega a fetchWithBackoff internamente en la estrategia,
          // o se asume manejada si el endpoint es estable.
          const response = UrlFetchApp.fetch(config.url, config);
          const json = JSON.parse(response.getContentText());
          parsedRes = s.parseResponse(json);      
          // ahora es responsabilidad exclusiva del adaptador de Exponential Backoff.
        }

        resultados.push(parsedRes);
        s.writeToSheet(parsedRes);        

      } catch (e) {
        Logger.log(`Error en ${s.name}: ${e.message}`);
      }      
    }

    // Imprimimos el log unificado de licencias antes de retornar los resultados
    if (typeof CELParserEngine !== 'undefined') {
       CELParserEngine.printDiscardedLogs();
    }
    return resultados;
  }
}