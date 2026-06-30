/**
 * Estrategia de Período de Gracia para la Verificación en 2 pasos (2SV).
 * Propósito: Auditar la ventana de tiempo que tienen los nuevos empleados para configurar su MFA antes de ser bloqueados.
 * https://docs.cloud.google.com/identity/docs/concepts/policy-api-concepts#reducers_for_settings
 * Referencia: security.two_step_verification_grace_period
 */
class GracePeriod2SVPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-013", 
        valueKey: "valorPrincipal",
        noteKey: "comentario013",
        riskKey: "riesgo013",
        scoreKey: "score013"
      }
    ];

    super("2SV Grace Period Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { census, policies } = globalContext;

    if (!census || !policies) {
      return this._buildErrorResponse("Falta el contexto global (censo o políticas).");
    }
    
    // =======================================================================
    // PASO 1: FILTRAR POLÍTICAS DE PERÍODO DE GRACIA
    // =======================================================================
    const gracePolicies = policies.filter(p => p.setting && p.setting.type.includes("security.two_step_verification_grace_period"));
    Logger.log(`[ID-013] Políticas de Período de Gracia encontradas: ${gracePolicies.length}`);

    // =======================================================================
    // PASO 2: ESCENARIO A - SILENCIO DE LA API
    // Si no hay configuración, la API omite los datos.
    // =======================================================================
    if (gracePolicies.length === 0) {
      Logger.log("[DEBUG ID-013] ALERTA: La API no retorna datos de período de gracia.");
      return {
        name: this.name,
        valorPrincipal: "Sin período de gracia",
        comentario013: "Práctica Segura (Fábrica): La API no reporta políticas anómalas. El 100% de la organización no tiene período de gracia, exigiendo MFA desde el día cero.",
        riesgo013: "Bajo",
        score013: this.calcularScoreDeRiesgo("Bajo")
      };
    }

    // =======================================================================
    // PASO 3: ESCENARIO B - EVALUAR POLÍTICA RAÍZ
    // Buscamos la regla general y traducimos los segundos a un formato humano.
    // =======================================================================
    const rootPolicy = gracePolicies.find(p => !(p.query || "").includes("entity."));
    
    let rootSeconds = 0; // Por defecto asumimos 0 (sin gracia)
    
    if (rootPolicy && rootPolicy.setting) {
      rootSeconds = this._extractSeconds(rootPolicy);
    }

    const { estadoPrincipal, riesgoRaiz } = this._evaluateGracePeriod(rootSeconds);
    Logger.log(`[ID-013] Raíz de la Org: Período de gracia = ${rootSeconds}s -> ${estadoPrincipal}`);

    // =======================================================================
    // PASO 4: CALCULAR PORCENTAJE DE USUARIOS CON GRACIA SEGURA/VULNERABLE
    // Evaluamos a cuántos usuarios se les da un tiempo excesivo (> 7 días)
    // =======================================================================
    let usuariosConTiempoSeguro = 0; // <= 7 días (604800 segundos)
    let usuariosConTiempoLaxo = 0; // > 7 días
    
    for (const user of census) {
      const aplicables = gracePolicies.filter(p => CELParserEngine.evaluate(p, user));
      const politicaGanadora = PolicyReducerFactory.reduce(aplicables, "security.two_step_verification_grace_period");

      const userSeconds = this._extractSeconds(politicaGanadora);

      // Usamos 7 días de gracia (604,800 segundos) como umbral de seguridad
      if (userSeconds <= 604800) {
        usuariosConTiempoSeguro++;
      } else {
        usuariosConTiempoLaxo++;
      }
    }

    const totalUsuarios = usuariosConTiempoSeguro + usuariosConTiempoLaxo;
    
    // Calculamos el % de usuarios que NO superan los 7 días de gracia
    const porcentajeSeguros = totalUsuarios > 0 ? Math.round((usuariosConTiempoSeguro / totalUsuarios) * 100) : 0;
    
    // =======================================================================
    // PASO 5: CONSTRUIR RESULTADO
    // El comentario ahora refleja el porcentaje de usuarios dentro del umbral seguro.
    // =======================================================================
    let riesgo013, comentario013;
    if (porcentajeSeguros === 100) {
       riesgo013 = "Bajo";
       comentario013 = `Seguro: El 100% de los usuarios (${usuariosConTiempoSeguro}/${totalUsuarios}) tiene un período de gracia seguro (≤ 7 días).`;
    } else {
       riesgo013 = "Alto";
       comentario013 = `Riesgo de Exposición: Solo el ${porcentajeSeguros}% de los usuarios está en un umbral seguro. Existen cuentas con días de gracia excesivos (> 7 días).`;
    }
    
    Logger.log(`[ID-013] Métrica procesada. Riesgo Raíz: ${riesgo013}. Usuarios en umbral seguro (<=7 días): ${porcentajeSeguros}%`);

    return {
      name: this.name,
      valorPrincipal: estadoPrincipal, 
      comentario013: comentario013,
      riesgo013: riesgo013,
      score013: this.calcularScoreDeRiesgo(riesgo013)
    };
  }

  // =======================================================================
  // HELPER 1: Extrae la duración en formato crudo y la convierte en segundos enteros
  // =======================================================================
  _extractSeconds(policy) {
    if (!policy || !policy.setting) return 0;

    const configNode = policy.setting.value || policy.setting;
    const graceNode = configNode.twoStepVerificationGracePeriod || configNode;
    
    // Extraemos la variable soportando múltiples sintaxis de Google
    const durationStr = graceNode.enrollmentGracePeriod || graceNode.enrollment_grace_period || graceNode.grace_period || graceNode.duration;

    if (durationStr) {
      // El formato de API es usualmente "604800s". Quitamos la 's' y convertimos a número.
      return parseInt(durationStr.toString().replace('s', ''), 10) || 0;
    }
    
    return 0;
  }

  // =======================================================================
  // HELPER 2: Traduce la cantidad de segundos a lenguaje humano y clasifica el riesgo
  // =======================================================================
  _evaluateGracePeriod(seconds) {
    if (seconds <= 0) {
      return { estadoPrincipal: "Sin período de gracia", riesgoRaiz: "Bajo" };
    }

    const dias = Math.round(seconds / 86400); // 86400 segundos = 1 día

    if (dias <= 7) {
      return { estadoPrincipal: `${dias} día(s)`, riesgoRaiz: "Bajo" }; // Umbral ideal (Onboarding normal)
    } else if (dias <= 30) {
      // De 1 a 4 semanas es un nivel laxo pero controlable
      const semanas = Math.round(dias / 7);
      return { estadoPrincipal: `${semanas} semana(s)`, riesgoRaiz: "Medio" };
    } else {
      // Más de un mes sin MFA es un riesgo grave de seguridad
      const meses = Math.round(dias / 30);
      return { estadoPrincipal: `${meses} mes(es)`, riesgoRaiz: "Alto" };
    }
  }

  // Traductor de texto a número (Score)
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return "";
  }

  // Handler de errores en memoria
  _buildErrorResponse(msg) {
    Logger.log(`[ID-013] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR EN MEMORIA",
      riesgo013: "",
      score013: "",
      comentario013: msg
    };
  }
}