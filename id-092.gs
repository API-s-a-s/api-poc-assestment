/**
 * Estrategia para auditar la existencia de alias de dominio de prueba en Google Workspace.
 * Evalúa si existen dominios con el sufijo '.test-google-a.com' aprovisionados en el tenant.
 * Utiliza Admin SDK Directory API (v1)
 * Desarrollada desde cero con lógica de negocio y comentarios inyectados para el ID-092.
 */
class TestDomainAliasStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-092
    const configIDs = [
      { 
        id: "ID-092", 
        valueKey: "valorPrincipal", // Retornará la cantidad (entero) de dominios de prueba encontrados
        noteKey: "comentario092",
        riskKey: "riesgo092",
        scoreKey: "score092"
      }
    ];

    super("Test Domain Alias Audit", configIDs);
    this.customerId = customerId;
    
    // Endpoint directo a la API de Directory para listar los dominios del cliente
    this.url = `https://admin.googleapis.com/admin/directory/v1/customer/${customerId}/domains`;
    this.category = "Email y DNS";
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
    Logger.log(`[DEBUG ID-092] Iniciando TestDomainAliasStrategy.evaluateInMemory para customerId: ${this.customerId}`);
    let testDomainCount = 0;
    let jsonRaw = null;

    try {
      // Usamos el servicio avanzado AdminDirectory para evadir problemas de Auth directos
      const response = AdminDirectory.Domains.list(this.customerId);
      jsonRaw = response;
      
      if (response && response.domains && response.domains.length > 0) {
        Logger.log(`[DEBUG ID-092] Dominios obtenidos de AdminDirectory API: ${response.domains.length}`);
        response.domains.forEach((domainObj, idx) => {
          const domainName = (domainObj.domainName || "").toLowerCase();
          const isTestDomain = domainName.endsWith('.test-google-a.com');
          Logger.log(`[DEBUG ID-092] Dominio #${idx + 1}: ${domainName} | ¿Es test domain?: ${isTestDomain}`);
          if (isTestDomain) {
            testDomainCount++;
          }
        });
      } else {
        Logger.log(`[DEBUG ID-092] No se retornaron dominios en la respuesta de AdminDirectory API.`);
      }
    } catch (e) {
      Logger.log(`[ERROR] Test Domain Alias Audit: ${e.message}`);
      return { 
        name: this.name, 
        raw: e.message,
        valorPrincipal: "ERROR",
        riesgo092: "Medio",
        score092: 2,
        comentario092: "Error de lectura, conectividad o permisos insuficientes en la API de Admin Directory que impide extraer el listado de dominios registrados en el tenant."
      };
    }

    let riesgo092, comentario092;

    if (testDomainCount === 0) {
      riesgo092 = "Bajo";
      comentario092 = "No se encontraron alias de dominio de prueba predeterminados como *.test-google-a.com.";
    } else {
      riesgo092 = "Medio";
      comentario092 = "Se encontraron dominios *.test-google-a.com activos en el entorno.";
    }

    Logger.log(`[LOG] Test Domain Alias Audit: Se detectaron ${testDomainCount} dominios de prueba. | Riesgo: ${riesgo092}`);

    return {
      name: this.name,
      raw: jsonRaw,
      valorPrincipal: testDomainCount,
      comentario092: comentario092,
      riesgo092: riesgo092,
      score092: this.calcularScoreDeRiesgo(riesgo092)
    };
  }
}