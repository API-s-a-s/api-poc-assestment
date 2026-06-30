/**
 * Estrategia de Enrolamiento en la Verificación en 2 pasos (MFA).
 * Propósito: Auditar si los usuarios tienen PERMITIDO activar el segundo factor.
 * Referencia: https://cloud.google.com/identity/docs/concepts/supported-policy-api-settings
 */
class TwoStepVerificationEnrollmentPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-007", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario007", 
        riskKey: "riesgo007", 
        scoreKey: "score007" 
      }
    ];
    super("2-Step Verification Enrollment Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;

    if (!policies) {
      return this._buildErrorResponse("Falta el contexto global.");
    }

    // =======================================================================
    // PASO 1: FILTRAR LAS POLÍTICAS DE MFA
    // Buscamos usando .includes() para evitar errores con prefijos de Google
    // =======================================================================
    const mfaPolicies = policies.filter(p => p.setting && p.setting.type.includes("security.two_step_verification_enrollment"));

    let respuestaConcreta;
    let riesgo007, comentario007;

    // =======================================================================
    // PASO 2: MANEJAR EL "SILENCIO" DE LA API (VALOR DE FÁBRICA)
    // A diferencia de las contraseñas, Google permite el MFA por defecto.
    // Si la lista viene vacía, asumimos que nadie lo ha bloqueado.
    // =======================================================================
    if (mfaPolicies.length === 0) {
      respuestaConcreta = "Habilitado";
      riesgo007 = "Bajo";
      comentario007 = "Los usuarios tienen habilitada la opción para inscribirse en la verificación en dos pasos (MFA).";
    } 
    // =======================================================================
    // PASO 3: EVALUAR LA POLÍTICA EFECTIVA DE LA RAÍZ
    // Usamos el Reducer para encontrar la política organizativa ganadora.
    // =======================================================================
    else {
      // Encontrar la política efectiva para la OU Raíz
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(mfaPolicies, "security.two_step_verification_enrollment");

      // Si la política ganadora lo permite, la organización está a salvo
      if (this._isEnrollmentAllowed(rootPolicy)) {
        respuestaConcreta = "Habilitado";
        riesgo007 = "Bajo";
        comentario007 = "Los usuarios tienen habilitada la opción para inscribirse en la verificación en dos pasos (MFA).";
      } 
      // Si la ganadora dice false, significa que un admin prohibió usar MFA
      else {
        respuestaConcreta = "Deshabilitado";
        riesgo007 = "Alto";
        comentario007 = "Los usuarios tienen bloqueada la capacidad de activar la verificación en dos pasos por sí mismos.";
      }
    }

    return {
      name: this.name, 
      valorPrincipal: respuestaConcreta, 
      comentario007: comentario007,
      riesgo007: riesgo007, 
      score007: this.calcularScoreDeRiesgo(riesgo007)
    };
  }

  // Función auxiliar para leer si el JSON permite el enrolamiento
  _isEnrollmentAllowed(policy) {
    if (!policy || !policy.setting) return false;
    
    // Leemos de 'value' si el extractor global lo hidrató, o directo de 'setting'
    const configNode = policy.setting.value || policy.setting;
    
    // Evaluamos ambas versiones de la variable que usa Google
    return (configNode.allowEnrollment === true || configNode.allow_enrollment === true);
  }

  // Convierte el texto "Alto", "Medio", "Bajo" en un número (Score)
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const r = nivelRiesgo.toString().trim().toLowerCase();
    if (r === "alto") return 1;
    if (r === "medio") return 2;
    if (r === "bajo") return 3;
    return "";
  }

  // En caso de que el script falle antes de procesar
  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo007: "", score007: "", comentario007: msg };
  }
}