/**
 * Estrategia para auditar la configuración del acceso IMAP en Gmail.
 * Evalúa si los usuarios tienen permitido sincronizar correos mediante protocolos heredados.
 */
class GmailImapAccessStrategy extends ApiStrategy {
  /**
   * Constructor de la estrategia.
   * @param {string} customerId - ID único del cliente en Google Workspace.
   */
  constructor(customerId) {
    // 1. Matriz de configuración requerida por la arquitectura base para vincular con Google Sheets
    const configIDs = [
      { 
        id: "ID-063", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario063",
        riskKey: "riesgo063",
        scoreKey: "score063"
      }
    ];

    super("Gmail IMAP Access Audit", configIDs);
    this.category = "Email y DNS";
  }

  /**
   * Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico (Score).
   */
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return null;
  }

  /**
   * Procesa la respuesta JSON cruda de la API de Google y aplica reglas de negocio inyectadas.
   */
    evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    const gmailPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.imap_access"));

    let isImapAccessEnabled = false;
    let rawData = null;

    if (gmailPolicies.length === 0) {
      // Por defecto, asumimos que no está habilitado explícitamente
      isImapAccessEnabled = false;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.imap_access");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-063] Política raíz efectiva encontrada: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const setting = rootPolicy.setting;
        const imapNode = setting.gmailImapAccess || setting.imapAccess || setting.value || setting;
        Logger.log(`[DEBUG ID-063] imapNode extraído: ${JSON.stringify(imapNode)}`);
        
        if (imapNode.enableImapAccess === true || imapNode.enable_imap_access === true || 
            (imapNode.state && imapNode.state.toUpperCase() === 'ENABLED')) {
          isImapAccessEnabled = true;
        }
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo063, comentario063;

    if (isImapAccessEnabled) {
      // Caso 1: IMAP está habilitado (Permisivo / Riesgo Alto)
      respuestaConcreta = "Habilitado";
      riesgo063 = "Alto";
      comentario063 = "El acceso por protocolo IMAP se encuentra habilitado en el dominio. Esto permite a los usuarios sincronizar y extraer correos electrónicos hacia clientes locales no autorizados o aplicaciones de terceros que evaden las directivas avanzadas de acceso condicional y el aprovisionamiento moderno basado en OAuth.";
    } else {
      // Caso 2: IMAP está deshabilitado (Restrictivo / Seguro)
      respuestaConcreta = "Deshabilitado";
      riesgo063 = "Bajo";
      comentario063 = "El acceso IMAP está deshabilitado de forma estricta en el tenant. Se bloquea el uso de credenciales en aplicaciones nativas o clientes de correo tradicionales no controlados, forzando el uso seguro de canales autorizados mediante mecanismos modernos de autenticación.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Gmail IMAP Access Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo063}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario063: comentario063,
      riesgo063: riesgo063,
      score063: this.calcularScoreDeRiesgo(riesgo063)
    };
    }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo063: "Medio", score063: 2, comentario063: msg };
  }
}