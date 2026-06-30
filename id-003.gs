/**
 * Estrategia de Políticas de Contraseña (En Memoria).
 * Propósito: Auditar si la organización exige contraseñas fuertes (STRONG).
 * Referencia: https://docs.cloud.google.com/identity/docs/concepts/supported-policy-api-settings?hl=es-419&authuser=3#security_settings
 */
class StrongPasswordPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-003", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario003", 
        riskKey: "riesgo003", 
        scoreKey: "score003" 
      }
    ];
    
    super("Strong Password Policy Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { census, policies } = globalContext;

    if (!census || !policies) {
      return this._buildErrorResponse("Falta el contexto global (censo o políticas).");
    }
    
    // =======================================================================
    // PASO 1: FILTRAR LAS POLÍTICAS DE CONTRASEÑA
    // Buscamos cualquier configuración que contenga "security.password"
    // =======================================================================
    const passwordPolicies = policies.filter(p => p.setting && p.setting.type.includes("security.password"));
    Logger.log(`[ID-003] Políticas de contraseñas encontradas en memoria: ${passwordPolicies.length}`);

    // =======================================================================
    // PASO 2: MANEJAR EL "SILENCIO" DE LA API
    // Si Google no devuelve nada, significa que no hay configuraciones 
    // personalizadas. Como acordamos, imprimimos "empty" en este caso.
    // =======================================================================
    if (passwordPolicies.length === 0) {
      Logger.log("[DEBUG ID-003] ALERTA: La API no retorna datos para contraseñas. Asumiendo configuración de fábrica (WEAK).");
      return {
        name: this.name,
        valorPrincipal: "Contraseñas Débiles",
        comentario003: "La organización no tiene configuradas políticas personalizadas de contraseñas. Por defecto de fábrica, se permiten contraseñas débiles.",
        riesgo003: "Alto",
        score003: this.calcularScoreDeRiesgo("Alto")
      };
    }

    // =======================================================================
    // PASO 3: ENCONTRAR LA POLÍTICA RAÍZ (LA REGLA GENERAL)
    // Buscamos dinámicamente el ID de la OU raíz y reducimos la política ganadora.
    // =======================================================================
    const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(passwordPolicies, "security.password");
    
    let rootStrength = "Desconocido"; // Fuerza de la contraseña (STRONG o WEAK)
    let isRootEnforced = false;       // ¿Obliga a cambiarla en el próximo login?
    
    // Extraemos los valores de la política raíz
    if (rootPolicy && rootPolicy.setting) {
      const configNode = rootPolicy.setting.value || rootPolicy.setting;
      const pwdNode = configNode.password || configNode; 
      
      rootStrength = pwdNode.allowedStrength || "WEAK";
      isRootEnforced = pwdNode.enforceRequirementsAtLogin === true;
    }

    // Formateamos el texto principal
    let estadoPrincipal = rootStrength === "STRONG" ? "Contraseñas Fuertes" : "Contraseñas Débiles";
    
    Logger.log(`[ID-003] Raíz de la Org: Fuerza='${rootStrength}', Forzado=${isRootEnforced}`);

    // =======================================================================
    // PASO 4: CALCULAR PORCENTAJE DE USUARIOS QUE CUMPLEN
    // Pasamos a los usuarios por el "embudo" del motor CEL para ver si tienen 
    // políticas excepcionales (grupos, licencias) que anulen la regla raíz.
    // =======================================================================
    let usuariosCumplen = 0;
    let usuariosNoCumplen = 0;
    
    for (const user of census) {
      // 1. Vemos qué políticas aplican a este usuario en particular
      const aplicables = passwordPolicies.filter(p => CELParserEngine.evaluate(p, user));
      // 2. Resolvemos conflictos (si aplica más de una política, gana la más estricta)
      const politicaGanadora = PolicyReducerFactory.reduce(aplicables, "security.password");

      // 3. Verificamos si la política ganadora exige contraseña FUERTE
      if (this._isPolicyStrong(politicaGanadora)) {
        usuariosCumplen++;
      } else {
        usuariosNoCumplen++;
      }
    }

    const totalUsuarios = usuariosCumplen + usuariosNoCumplen;
    const porcentajeCumplimiento = totalUsuarios > 0 ? Math.round((usuariosCumplen / totalUsuarios) * 100) : 0;
    
    // =======================================================================
    // PASO 5: ASIGNAR RIESGO Y CONSTRUIR RESULTADO
    // El riesgo depende de si la política principal de la empresa es STRONG o no.
    // =======================================================================
    let riesgo = (rootStrength === "STRONG") ? "Bajo" : "Alto";
    let comentario = (rootStrength === "STRONG")
      ? `El ${porcentajeCumplimiento}% de los usuarios tiene exigida una política de contraseñas fuertes.`
      : `Las políticas actuales permiten el uso de contraseñas débiles en la raíz del dominio. Solo el ${porcentajeCumplimiento}% de los usuarios está forzado a usar contraseñas fuertes mediante excepciones.`;
    
    return {
      name: this.name,
      valorPrincipal: estadoPrincipal, 
      comentario003: comentario,
      riesgo003: riesgo,
      score003: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  // Función auxiliar para saber si una política exige contraseña FUERTE
  _isPolicyStrong(policy) {
    if (!policy || !policy.setting) return false;
    const configNode = policy.setting.value || policy.setting;
    const pwdNode = configNode.password || configNode;
    
    return pwdNode.allowedStrength === "STRONG";
  }

  // Convierte el texto "Alto", "Medio", "Bajo" en un número (Score)
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return "";
  }

  // En caso de que el script falle antes de procesar
  _buildErrorResponse(msg) {
    Logger.log(`[ID-003] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR EN MEMORIA", riesgo003: "", score003: "", comentario003: msg };
  }
} 