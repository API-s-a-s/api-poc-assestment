/**
 * Estrategia para auditar las listas de remitentes aprobados (Spam Override Lists) de Gmail.
 * Evalúa cuántos remitentes o dominios tienen permitido saltarse el filtro de spam.
 */
class GmailSpamOverrideListsStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-078
    const configIDs = [
      { 
        id: "ID-078", 
        valueKey: "valorPrincipal", // Retornará el número entero de remitentes aprobados
        noteKey: "comentario078",
        riskKey: "riesgo078",
        scoreKey: "score078"
      }
    ];

    super("Gmail Spam Override Lists Audit", configIDs);
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

    const gmailPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.spam_override_lists"));

    let overrideCount = 0;
    let rawData = null;

    if (gmailPolicies.length === 0) {
      // Por defecto, asumimos lista vacía
      overrideCount = 0;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.spam_override_lists");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-078] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-078] valueNode: ${JSON.stringify(valueNode)}`);
        
        // Buscamos el arreglo de direcciones o dominios exentos
        const senders = valueNode.approvedSenders || valueNode.addresses || valueNode.senders || [];
        overrideCount = senders.length;
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let riesgo078, comentario078;

    if (overrideCount === 0) {
      // Caso 1: Lista vacía (Seguro)
      riesgo078 = "Bajo";
      comentario078 = "La lista de remitentes aprobados (Spam Override Lists) se encuentra vacía. No existen dominios ni direcciones de correo con excepciones configuradas para saltarse el motor antispam de Google, lo que garantiza que todo el tráfico entrante sea evaluado de manera imparcial por las heurísticas de seguridad.";
    } else {
      // Caso 2: Existen remitentes exentos (Riesgo Medio)
      riesgo078 = "Medio";
      comentario078 = "Indica la cantidad de remitentes o dominios configurados explícitamente en la lista de aprobados (Spam Override). Estos remitentes evaden las validaciones de reputación del filtro de spam, lo que requiere auditoría periódica para asegurar que no se estén exponiendo las bandejas de entrada a cuentas externas comprometidas.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Spam Override Lists Audit: Se detectaron ${overrideCount} remitentes exentos del filtro de spam. | Riesgo: ${riesgo078}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: overrideCount,
      comentario078: comentario078,
      riesgo078: riesgo078,
      score078: this.calcularScoreDeRiesgo(riesgo078)
    };
    }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo078: "Medio", score078: 2, comentario078: msg };
  }
}