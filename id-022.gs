/**
 * Estrategia para auditar los Códigos de Seguridad del Programa de Protección Avanzada.
 * Utiliza la Cloud Identity API (v1)
 * Evalúa si los usuarios de APP pueden generar códigos, lo cual es un riesgo frente al phishing.
 */
class AdvancedProtectionPolicyCodesStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-022", 
        valueKey: "valorPrincipal",
        noteKey: "comentario022",
        riskKey: "riesgo022",
        scoreKey: "score022"
      }
    ];

    super("Advanced Protection Security Codes Audit", configIDs);
    
    // El endpoint es el mismo para toda la suite de Protección Avanzada
    const filter = `customer=="customers/${customerId}" && setting.type=="settings/security.advanced_protection_program"`;
    this.url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}`;
    this.category = "Identidad y autenticación";
  }

  getRequestConfig() {
    return {
      url: this.url,
      method: "get",
      muteHttpExceptions: true
    };
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return "";
  }

  parseResponse(json) {
    if (json.error) {
      Logger.log(`[ERROR] APP Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR_API",
        riesgo022: "Medio",
        score022: 2,
        comentario022: "Error de conectividad vía API Cloud Identity."
      };
    }

    const policies = json.policies || [];

    // =======================================================================
    // PASO 1: EXTRAER LA POLÍTICA EFECTIVA A NIVEL ORGANIZATIVO (RAÍZ)
    // Buscamos la regla que aplica a toda la organización (sin "entity.")
    // =======================================================================
    const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(policies, "security.advanced_protection_program");
    let securityCodeOption = "Sin configurar (Default)";

    if (rootPolicy && rootPolicy.setting) {
      // Extraemos el nodo de configuración soportando las variaciones de la API
      const configNode = rootPolicy.setting.advancedProtectionProgram || rootPolicy.setting.value || rootPolicy.setting;
      
      if (configNode && configNode.securityCodeOption) {
        securityCodeOption = configNode.securityCodeOption;
      }
    } else if (policies.length === 0) {
      securityCodeOption = "NO_POLICIES_RETURNED";
    }

    // =======================================================================
    // PASO 2: INTERPRETAR EL RIESGO SEGÚN EL ENUMERADOR DE GOOGLE
    // =======================================================================
    let riesgo022, comentario022;

    switch (securityCodeOption) {
      case "CODES_NOT_ALLOWED":
        riesgo022 = "Bajo";
        comentario022 = "Configuración segura. Los usuarios de Protección Avanzada tienen PROHIBIDA la generación de códigos de seguridad. Esto fuerza el uso exclusivo de llaves físicas, mitigando ataques de phishing avanzados.";
        break;

      case "ALLOWED_WITHOUT_REMOTE_ACCESS":
        riesgo022 = "Medio";
        comentario022 = "Riesgo intermedio. Se permite generar códigos, pero sin acceso remoto. Si bien no es la configuración de máxima seguridad, cuenta con mitigaciones parciales para evitar abusos a distancia.";
        break;

      case "ALLOWED_WITH_REMOTE_ACCESS":
        riesgo022 = "Alto";
        comentario022 = "VULNERABILIDAD: Se permite generar códigos de seguridad incluyendo acceso remoto. Esto rompe la filosofía del Programa de Protección Avanzada, permitiendo que atacantes remotos utilicen phishing de códigos para vulnerar cuentas críticas.";
        break;

      case "Sin configurar (Default)":
      case "NO_POLICIES_RETURNED":
      default:
        riesgo022 = "Medio";
        comentario022 = "No hay una directiva explícita asignada a la OU raíz para bloquear los códigos de seguridad del Programa de Protección Avanzada. Se asume el comportamiento por defecto de Google.";
        break;
    }

    // Trazabilidad técnica para los logs de Apps Script
    Logger.log(`[LOG] APP Security Codes Audit: OU Raíz -> ${securityCodeOption} | Riesgo: ${riesgo022}`);

    // =======================================================================
    // PASO 3: RETORNAR RESULTADO
    // =======================================================================
    return {
      name: this.name,
      raw: json,
      valorPrincipal: securityCodeOption, // Se inserta el valor literal de la API
      comentario022: comentario022,
      riesgo022: riesgo022,
      score022: this.calcularScoreDeRiesgo(riesgo022)
    };
  }
}