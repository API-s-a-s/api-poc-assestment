/**
 * Estrategia para auditar las listas de remitentes bloqueados (Blocked Sender Lists) de Gmail.
 * Evalúa la cantidad de dominios y correos explícitamente vetados por la organización.
 */
class GmailBlockedSenderListsStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-082
    const configIDs = [
      { 
        id: "ID-082", 
        valueKey: "valorPrincipal", // Retornará el número entero de remitentes bloqueados
        noteKey: "comentario082",
        riskKey: "riesgo082",
        scoreKey: "score082"
      }
    ];

    super("Gmail Blocked Senders Audit", configIDs);
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

    const gmailPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.blocked_sender_lists"));

    let blockedCount = 0;
    let rawData = null;

    if (gmailPolicies.length === 0) {
      // Por defecto, asumimos lista vacía
      blockedCount = 0;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.blocked_sender_lists");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-082] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-082] valueNode: ${JSON.stringify(valueNode)}`);
        
        // Buscamos el arreglo de direcciones o dominios bloqueados
        const senders = valueNode.blockedSenders || valueNode.addresses || valueNode.senders || [];
        blockedCount = senders.length;
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let riesgo082, comentario082;

    if (blockedCount === 0) {
      // Caso 1: Lista vacía (Riesgo Medio por falta de bloqueos manuales)
      riesgo082 = "Medio";
      comentario082 = "La lista de remitentes bloqueados (Blocklist) se encuentra vacía. La organización no ha configurado bloqueos explícitos para dominios o direcciones de correo maliciosas comprobadas, dependiendo exclusivamente de los filtros automatizados y globales de Google Workspace.";
    } else {
      // Caso 2: Existen remitentes vetados (Seguro / Proactivo)
      riesgo082 = "Bajo";
      comentario082 = "Indica la cantidad de dominios o direcciones de correo electrónico explícitamente vetados. La organización mantiene listas de bloqueo activas como medida proactiva para rechazar correos provenientes de atacantes conocidos, mitigando campañas recurrentes de phishing o spam.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Blocked Senders Audit: Se detectaron ${blockedCount} remitentes en la lista negra. | Riesgo: ${riesgo082}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: blockedCount,
      comentario082: comentario082,
      riesgo082: riesgo082,
      score082: this.calcularScoreDeRiesgo(riesgo082)
    };
    }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo082: "Medio", score082: 2, comentario082: msg };
  }
}