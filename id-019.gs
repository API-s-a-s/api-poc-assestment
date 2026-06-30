/**
 * Estrategia de Desafío de Inicio de Sesión mediante ID de Empleado (En Memoria).
 * Propósito: Auditar matemáticamente qué porcentaje de los usuarios tienen exigido 
 * el Employee ID como medida extra de verificación ante accesos sospechosos.
 * Referencia: security.login_challenges
 */
class EmployeeIdLoginChallengePolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-019", 
        valueKey: "valorPrincipal",
        noteKey: "comentario019",
        riskKey: "riesgo019",
        scoreKey: "score019"
      }
    ];

    super("Employee ID Login Challenge Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { census, policies } = globalContext;

    if (!census || !policies) {
      return this._buildErrorResponse("Falta el contexto global (censo o políticas).");
    }

    // =======================================================================
    // PASO 1: FILTRAR LAS POLÍTICAS DE DESAFÍOS DE LOGIN
    // =======================================================================
    const challengePolicies = policies.filter(p => p.setting && p.setting.type.includes("security.login_challenges"));
    Logger.log(`[ID-019] Políticas de Desafío de Login encontradas: ${challengePolicies.length}`);

    // =======================================================================
    // PASO 2: ESCENARIO A - SILENCIO DE LA API (ESTADO DE FÁBRICA)
    // =======================================================================
    if (challengePolicies.length === 0) {
      Logger.log("[DEBUG ID-019] ALERTA: La API no retorna datos para desafíos de login.");
      return {
        name: this.name,
        valorPrincipal: "Deshabilitado (0%)",
        comentario019: "Oportunidad de Endurecimiento: La API no retorna configuraciones. Ningún usuario (0%) tiene habilitada la exigencia del ID de empleado como medida adicional ante accesos no habituales.",
        riesgo019: "Medio",
        score019: this.calcularScoreDeRiesgo("Medio")
      };
    }

    // =======================================================================
    // PASO 3: EVALUAR LA POLÍTICA RAÍZ
    // Buscamos dinámicamente el ID de la OU raíz y reducimos la política ganadora.
    // =======================================================================
    const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(challengePolicies, "security.login_challenges");
    let isRootEnabled = this._isChallengeEnabled(rootPolicy);
    const estadoPrincipal = isRootEnabled ? "Habilitado" : "Deshabilitado";

    // =======================================================================
    // PASO 4: CALCULAR PORCENTAJE DE COBERTURA EN EL CENSO
    // Evaluamos usuario por usuario para ver quién tiene habilitado el desafío
    // =======================================================================
    const totalUsuarios = census.length;
    
    if (totalUsuarios === 0) {
      return {
        name: this.name,
        valorPrincipal: "N/A",
        comentario019: "No hay usuarios en el censo para evaluar.",
        riesgo019: "Medio",
        score019: this.calcularScoreDeRiesgo("Medio")
      };
    }

    let usuariosHabilitados = 0;

    for (const user of census) {
      // Filtramos qué políticas aplican a este usuario
      const aplicables = challengePolicies.filter(p => CELParserEngine.evaluate(p, user));      
      // Resolvemos conflictos de jerarquía (Gana el sortOrder mayor)
      const politicaGanadora = PolicyReducerFactory.reduce(aplicables, "security.login_challenges");

      // Verificamos si la política ganadora le exige el Employee ID
      if (this._isChallengeEnabled(politicaGanadora)) {
        usuariosHabilitados++;
      }
    }

    const porcentajeHabilitados = Math.round((usuariosHabilitados / totalUsuarios) * 100);

    // =======================================================================
    // PASO 5: ASIGNAR RIESGO Y CONSTRUIR RESULTADO BASADO EN %
    // =======================================================================
    let riesgo019, comentario019, valorPrincipalFormateado;
    if (porcentajeHabilitados === 100) {
       riesgo019 = "Bajo";
       comentario019 = `Excelente cobertura. El 100% de los usuarios tiene configurado el desafío mediante ID de empleado como capa adicional.`;
       valorPrincipalFormateado = "Habilitado (100%)";
    } else if (porcentajeHabilitados === 0) {
       riesgo019 = "Medio";
       comentario019 = `Oportunidad de Endurecimiento: Ningún usuario (0%) tiene habilitada la exigencia del identificador de empleado como medida adicional.`;
       valorPrincipalFormateado = "Deshabilitado (0%)";
    } else {
       riesgo019 = "Medio";
       comentario019 = `Adopción parcial: El ${porcentajeHabilitados}% de los usuarios (${usuariosHabilitados}/${totalUsuarios}) tiene habilitado el desafío de ID de empleado.`;
       valorPrincipalFormateado = `Habilitado (${porcentajeHabilitados}%)`;
    }

    Logger.log(`[ID-019] Métrica procesada. Riesgo: ${riesgo019}. Cobertura: ${porcentajeHabilitados}%`);

    return {
      name: this.name,
      valorPrincipal: valorPrincipalFormateado,
      comentario019: comentario019,
      riesgo019: riesgo019,
      score019: this.calcularScoreDeRiesgo(riesgo019)
    };
  }

  // =======================================================================
  // HELPER: Valida si la política habilita el desafío del ID de empleado
  // =======================================================================
  _isChallengeEnabled(policy) {
    if (!policy || !policy.setting) return false;
    
    const configNode = policy.setting.value || policy.setting;
    const challengeNode = configNode.loginChallenges || configNode;
    
    // Evaluamos ambas versiones de la variable que usa Google (camelCase y snake_case)
    return (challengeNode.enableEmployeeIdChallenge === true || challengeNode.enable_employee_id_challenge === true);
  }

  // Traductor de texto a número (Score)
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const r = nivelRiesgo.toString().trim().toLowerCase();
    if (r === "alto") return 1;
    if (r === "medio") return 2;
    if (r === "bajo") return 3;
    return "";
  }

  // Handler de errores en memoria
  _buildErrorResponse(msg) {
    Logger.log(`[ID-019] ERROR: ${msg}`);
    return { 
      name: this.name, 
      valorPrincipal: "ERROR EN MEMORIA", 
      riesgo019: "", 
      score019: "", 
      comentario019: msg 
    };
  }
}