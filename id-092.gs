/**
 * Estrategia para auditar la existencia de alias de dominio de prueba en Google Workspace.
 * Evalúa si existen dominios con el sufijo '.test-google-a.com' aprovisionados en el tenant.
 * Utiliza Admin SDK Directory API (v1)
 */
class TestDomainAliasStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-092
    const configIDs = [
      { 
        id: "ID-092", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario092",
        riskKey: "riesgo092",
        scoreKey: "score092"
      }
    ];

    super("Test Domain Alias Audit", configIDs);
    
    // SOLUCIÓN: Faltaba inicializar this.customerId en la instancia
    this.customerId = customerId || "my_customer";
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
    let testDomainCount = 0;
    let jsonRaw = null;

    try {
      // Usamos el servicio avanzado AdminDirectory. 
      // Al haber fijado this.customerId, ahora la llamada viajará correctamente.
      const response = AdminDirectory.Domains.list(this.customerId);
      jsonRaw = response;
      
      if (response && response.domains && response.domains.length > 0) {
        response.domains.forEach(domainObj => {
          const domainName = (domainObj.domainName || "").toLowerCase();
          // Buscamos explícitamente el sufijo de dominios de prueba de Google
          if (domainName.endsWith('.test-google-a.com')) {
            testDomainCount++;
          }
        });
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

    let riesgo092, comentario092, valorPrincipalFormateado;

    if (testDomainCount === 0) {
      riesgo092 = "Bajo";
      valorPrincipalFormateado = "Deshabilitado";
      comentario092 = "No se encontraron alias de dominio de prueba predeterminados (como *.test-google-a.com). Esto minimiza la superficie de ataque y previene que actores maliciosos intenten evadir políticas de enrutamiento o esquemas de Single Sign-On (SSO) empleando el dominio de pruebas.";
    } else {
      riesgo092 = "Medio";
      valorPrincipalFormateado = `Habilitado (${testDomainCount})`;
      comentario092 = `Se detectaron ${testDomainCount} alias de dominio de prueba (ej. *.test-google-a.com) activos en el entorno. Aunque Google los aprovisiona por defecto para procesos de migración, se recomienda eliminarlos si no están en uso activo para evitar vectores de bypass de seguridad (SSO/Enrutamiento).`;
    }

    Logger.log(`[LOG] Test Domain Alias Audit: Se detectaron ${testDomainCount} dominios de prueba. | Riesgo: ${riesgo092}`);

    return {
      name: this.name,
      raw: jsonRaw,
      valorPrincipal: valorPrincipalFormateado,
      comentario092: comentario092,
      riesgo092: riesgo092,
      score092: this.calcularScoreDeRiesgo(riesgo092)
    };
  }
}