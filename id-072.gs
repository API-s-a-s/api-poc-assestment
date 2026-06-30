/**
 * Estrategia para auditar las directivas avanzadas de protección contra spoofing y autenticación en Gmail.
 * Evalúa si el dominio cuenta con escudos activos frente a ataques BEC y suplantación de nombres/dominios.
 */
class GmailSpoofingAndAuthenticationStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para asociar los resultados con el ID-072 en Google Sheets
    const configIDs = [
      { 
        id: "ID-072", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario072",
        riskKey: "riesgo072",
        scoreKey: "score072"
      }
    ];

    super("Gmail Spoofing and Authentication Safety Audit", configIDs);
    this.category = "Email y DNS";
  }

  // Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico (Score)
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

    const gmailPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.spoofing_and_authentication"));

    let isSpoofingProtectionEnabled = false;
    let rawData = null;

    if (gmailPolicies.length === 0) {
      // Por defecto, asumimos que no está habilitado
      isSpoofingProtectionEnabled = false;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.spoofing_and_authentication");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-072] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-072] valueNode: ${JSON.stringify(valueNode)}`);
        
        if (valueNode.enableSpoofingAndAuthentication === true || 
            (valueNode.state && valueNode.state.toUpperCase() === 'ENABLED')) {
          isSpoofingProtectionEnabled = true;
        }
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo072, comentario072;

    if (isSpoofingProtectionEnabled) {
      // Caso 1: Protección contra spoofing activa (Seguro)
      respuestaConcreta = "Habilitado";
      riesgo072 = "Bajo";
      comentario072 = "Las protecciones avanzadas contra suplantación de identidad (spoofing) y validación de autenticación de correo están habilitadas. El sistema analiza activamente los mensajes entrantes para bloquear intentos de phishing dirigidos, suplantación de nombres de ejecutivos o dominios homógrafos, y flujos que fallen los controles rigurosos de SPF/DKIM.";
    } else {
      // Caso 2: Sin protección avanzada (Riesgo Alto)
      respuestaConcreta = "Deshabilitado";
      riesgo072 = "Alto";
      comentario072 = "Las protecciones avanzadas contra spoofing y suplantadores de identidad en Gmail están deshabilitadas. La organización carece de defensas estrictas y algoritmos de IA para mitigar ataques de Business Email Compromise (BEC) y manipulación de cabeceras, incrementando severamente la exposición al engaño de los usuarios.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Spoofing & Auth Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo072}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario072: comentario072,
      riesgo072: riesgo072,
      score072: this.calcularScoreDeRiesgo(riesgo072)
    };
    }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo072: "Medio", score072: 2, comentario072: msg };
  }
}