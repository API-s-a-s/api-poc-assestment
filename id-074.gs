/**
 * Estrategia para auditar la lista de IPs permitidas en el filtro de spam de Gmail.
 * Evalúa cuántas direcciones IP están configuradas para evadir los controles antispam.
 */
class GmailSpamFilterIpAllowlistStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-074
    const configIDs = [
      { 
        id: "ID-074", 
        valueKey: "valorPrincipal", // Retornará el número entero de IPs en la lista blanca
        noteKey: "comentario074",
        riskKey: "riesgo074",
        scoreKey: "score074"
      }
    ];

    super("Gmail Spam Filter IP Allowlist Audit", configIDs);
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

    const gmailPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.email_spam_filter_ip_allowlist"));

    let allowedIpCount = 0;
    let rawData = null;

    if (gmailPolicies.length === 0) {
      // Por defecto, asumimos que no hay IPs permitidas (lista vacía)
      allowedIpCount = 0;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.email_spam_filter_ip_allowlist");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-074] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-074] valueNode: ${JSON.stringify(valueNode)}`);
        
        // Buscamos el arreglo de IPs
        const ips = valueNode.allowedIps || valueNode.ipAddresses || valueNode.ips || [];
        allowedIpCount = ips.length;
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let riesgo074, comentario074;

    if (allowedIpCount === 0) {
      // Caso 1: No hay IPs en la lista blanca (Seguro)
      riesgo074 = "Bajo";
      comentario074 = "La lista de direcciones IP permitidas (Allowlist) para evadir el filtro de spam se encuentra vacía. Todo el tráfico de correo entrante, sin importar su origen, está sujeto a la inspección estricta y a los motores de detección de amenazas de Google.";
    } else {
      // Caso 2: Existen IPs que evaden el spam (Riesgo Medio - Requiere revisión)
      riesgo074 = "Medio";
      comentario074 = "Indica la cantidad de direcciones IP externas que están configuradas explícitamente para evadir los controles antispam de Gmail. Esto requiere auditoría periódica, ya que los correos provenientes de estas IPs se entregarán directamente en las bandejas de entrada ignorando las heurísticas de seguridad.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Spam Filter IP Allowlist: Se detectaron ${allowedIpCount} IPs en la lista blanca. | Riesgo: ${riesgo074}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: allowedIpCount,
      comentario074: comentario074,
      riesgo074: riesgo074,
      score074: this.calcularScoreDeRiesgo(riesgo074)
    };
    }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo074: "Medio", score074: 2, comentario074: msg };
  }
}