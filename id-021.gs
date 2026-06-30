/**
 * Estrategia para auditar el Auto-enrolamiento del Programa de Protección Avanzada.
 * Utiliza la Cloud Identity API (v1)
 * Evalúa si "Habilita el registro de usuarios" está activado a nivel organizacional.
 */
class AdvancedProtectionPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-021", 
        valueKey: "valorPrincipal",
        noteKey: "comentario021",
        riskKey: "riesgo021",
        scoreKey: "score021"
      }
    ];

    super("Advanced Protection Self-Enrollment Audit", configIDs);
    
    // Filtro enfocado a las configuraciones de Protección Avanzada en API v1
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
        riesgo021: "Medio",
        score021: 2,
        comentario021: "Error de conectividad vía API Cloud Identity."
      };
    }

    const policies = json.policies || [];

    // =======================================================================
    // PASO 1: EXTRAER LA POLÍTICA EFECTIVA A NIVEL ORGANIZATIVO (RAÍZ)
    // =======================================================================
    const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(policies, "security.advanced_protection_program");

    let enableSelfEnrollment = null; // null = No configurado explícitamente

    if (rootPolicy && rootPolicy.setting) {
      const configNode = rootPolicy.setting.advancedProtectionProgram || rootPolicy.setting.value || rootPolicy.setting;
      if (configNode) {
        // Tolerancia a snake_case o camelCase
        if (configNode.enableAdvancedProtectionSelfEnrollment !== undefined) {
          enableSelfEnrollment = configNode.enableAdvancedProtectionSelfEnrollment;
        } else if (configNode.enable_advanced_protection_self_enrollment !== undefined) {
          enableSelfEnrollment = configNode.enable_advanced_protection_self_enrollment;
        }
      }
    }

    // =======================================================================
    // PASO 2: INTERPRETAR EL RIESGO SEGÚN EL REQUERIMIENTO
    // =======================================================================
    let respuestaConcreta;
    let riesgo021, comentario021;

    if (enableSelfEnrollment === true) {
      respuestaConcreta = "Habilitado";
      riesgo021 = "Bajo";
      comentario021 = "La política efectiva a nivel organizacional PERMITE el auto-enrolamiento ('Habilita el registro de usuarios'). Los empleados pueden unirse al Programa de Protección Avanzada de forma proactiva.";
    } else if (enableSelfEnrollment === false) {
      respuestaConcreta = "Deshabilitado";
      riesgo021 = "Alto";
      comentario021 = "La política efectiva a nivel organizacional BLOQUEA el auto-enrolamiento ('Deshabilita el registro de usuarios'). Los usuarios no pueden unirse al Programa de Protección Avanzada por su cuenta.";
    } else {
      respuestaConcreta = "Sin configurar (Default)";
      riesgo021 = "Medio";
      comentario021 = "No existe una directiva técnica explícita en la OU raíz que gobierne el auto-enrolamiento en el Programa de Protección Avanzada. Aplica el estado por defecto de Google.";
    }

    // Trazabilidad técnica
    Logger.log(`[LOG] APP Self-Enrollment Audit: OU Raíz -> ${respuestaConcreta} | Riesgo: ${riesgo021}`);

    // 3. RETORNAR RESULTADO
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario021: comentario021,
      riesgo021: riesgo021,
      score021: this.calcularScoreDeRiesgo(riesgo021)
    };
  }
}