/**
 * Estrategia para auditar las Reglas de Cumplimiento de Contenido en Gmail (DLP).
 * Evalúa cuántas reglas están configuradas para inspeccionar y restringir correos por palabras clave o patrones.
 * Utiliza Cloud Identity API (v1beta1)
 * Desarrollada desde cero con lógica de negocio y comentarios inyectados para el ID-083.
 */
class GmailContentComplianceStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-083
    const configIDs = [
      { 
        id: "ID-083", 
        valueKey: "valorPrincipal", // Retornará el número entero de reglas configuradas
        noteKey: "comentario083",
        riskKey: "riesgo083",
        scoreKey: "score083"
      }
    ];

    super("Gmail Content Compliance Audit (DLP)", configIDs);
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
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    const gmailPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.content_compliance"));

    let rulesCount = 0;
    let rawData = null;

    if (gmailPolicies.length === 0) {
      // Por defecto, asumimos que no hay reglas
      rulesCount = 0;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.content_compliance");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-083] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-083] valueNode: ${JSON.stringify(valueNode)}`);
        
        // Buscamos el arreglo de reglas (DLP, regex, palabras clave)
        const rules = valueNode.rules || valueNode.complianceRules || valueNode.settingRules || [];
        rulesCount = rules.length;
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let riesgo083, comentario083;

    if (rulesCount === 0) {
      // Caso 1: Cero reglas de cumplimiento (Riesgo Alto por fuga de datos)
      riesgo083 = "Alto";
      comentario083 = "No se encontraron reglas de cumplimiento de contenido (Content Compliance) configuradas. La organización carece de controles automatizados de Prevención de Pérdida de Datos (DLP) en los correos electrónicos, lo que permite la posible exfiltración de información sensible (como datos financieros o PII) sin restricciones ni alertas analíticas.";
    } else {
      // Caso 2: Existen reglas configuradas (Seguro / Maduro)
      riesgo083 = "Bajo";
      comentario083 = "Indica la cantidad de reglas activas de cumplimiento de contenido. La organización cuenta con políticas de Prevención de Pérdida de Datos (DLP) estructuradas para inspeccionar y controlar el flujo de correos que contienen palabras clave específicas, patrones regulados o información confidencial.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Content Compliance Audit: Se detectaron ${rulesCount} reglas de DLP/Cumplimiento. | Riesgo: ${riesgo083}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: rulesCount,
      comentario083: comentario083,
      riesgo083: riesgo083,
      score083: this.calcularScoreDeRiesgo(riesgo083)
    };
    }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo083: "Medio", score083: 2, comentario083: msg };
  }
}