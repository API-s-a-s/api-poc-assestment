/**
 * Estrategia de Reutilización de Contraseñas (En Memoria).
 * Propósito: Auditar si la organización permite reciclar contraseñas antiguas.
 * Referencia: https://cloud.google.com/identity/docs/concepts/supported-policy-api-settings
 */
class PasswordReusePolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-004", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario004", 
        riskKey: "riesgo004", 
        scoreKey: "score004" 
      }
    ];
    
    super("Password Reuse Policy Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { census, policies } = globalContext;

    if (!census || !policies) {
      return this._buildErrorResponse("Falta el contexto global (censo o políticas).");
    }
    
    // 1. FILTRAR POLÍTICAS DE CONTRASEÑA
    const passwordPolicies = policies.filter(p => p.setting && p.setting.type.includes("security.password"));

    // 2. ESCENARIO A: SILENCIO DE LA API (Eliminado)
    // Dejamos que el motor procese. Al no haber políticas, asumirá la reutilización como 'true' (por defecto de fábrica).
    // 3. ESCENARIO B: EVALUAR POLÍTICA RAÍZ
    const rootPolicy = passwordPolicies.find(p => !(p.query || "").includes("entity."));
    
    let isReuseAllowed = true; // Por defecto de fábrica, Google permite reutilizar
    
    if (rootPolicy && rootPolicy.setting) {
      const configNode = rootPolicy.setting.value || rootPolicy.setting;
      const pwdNode = configNode.password || configNode; 
      
      // LOG FORENSE: Mostramos exactamente qué encontró el script en la variable
      Logger.log(`[DEBUG ID-004] Inspección del nodo 'password' de la raíz: ${JSON.stringify(pwdNode)}`);
      
      // Verificamos explícitamente el valor configurado de la variable allowReuse
      isReuseAllowed = pwdNode.allowReuse !== false; 
    }

    const estadoPrincipal = isReuseAllowed ? "Permitido" : "Bloqueado";
    Logger.log(`[ID-004] Raíz de la Org: Reutilización de contraseña (allowReuse) = ${estadoPrincipal}`);

    // 4. CALCULAR PORCENTAJE DE USUARIOS (CENSO)
    let usuariosPermitidos = 0;
    let usuariosBloqueados = 0;
    
    // LOG FORENSE: Explicamos qué hace el motor
    Logger.log(`[DEBUG ID-004] Iniciando escaneo de ${census.length} usuarios usando CELParserEngine para buscar excepciones...`);

    for (const user of census) {
      const aplicables = passwordPolicies.filter(p => CELParserEngine.evaluate(p, user));   
      const politicaGanadora = PolicyReducerFactory.reduce(aplicables, "security.password");
      // Corrección de herencia: Si hay política ganadora se evalúa, si no, hereda de la raíz.
      const userAllowed = politicaGanadora ? this._isReuseAllowed(politicaGanadora) : isReuseAllowed;

      if (userAllowed) {
        usuariosPermitidos++;
      } else {
        usuariosBloqueados++;
      }
    }

    const totalUsuarios = usuariosPermitidos + usuariosBloqueados;
    const porcentajePermitidos = totalUsuarios > 0 ? Math.round((usuariosPermitidos / totalUsuarios) * 100) : 0;
    const porcentajeBloqueados = totalUsuarios > 0 ? Math.round((usuariosBloqueados / totalUsuarios) * 100) : 0;
    
    // 5. ASIGNAR RIESGO Y CONSTRUIR RESULTADO
    // Permitir la reutilización es un riesgo de seguridad (Alto). Bloquearlo es seguro (Bajo).
    let riesgo = isReuseAllowed ? "Alto" : "Bajo";
    
    let comentario = isReuseAllowed 
      ? `La reutilización de contraseñas está permitida. El ${porcentajePermitidos}% de los usuarios puede reciclar claves antiguas.`
      : `La reutilización de contraseñas está bloqueada desde la raíz. El ${porcentajeBloqueados}% de los usuarios tiene prohibido reciclar claves antiguas.`;
    
    Logger.log(`[ID-004] Métrica procesada. Riesgo: ${riesgo}. Bloqueado en: ${porcentajeBloqueados}% de usuarios.`);

    return {
      name: this.name,
      valorPrincipal: estadoPrincipal, 
      comentario004: comentario,
      riesgo004: riesgo,
      score004: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  // Helper: Verifica si la política permite la reutilización leyendo la variable allowReuse
  _isReuseAllowed(policy) {
    if (!policy || !policy.setting) return true; // Si no hay regla, Google lo permite por defecto
    
    const configNode = policy.setting.value || policy.setting;
    const pwdNode = configNode.password || configNode;
    
    // Si la variable allowReuse dice estrictamente 'false', está bloqueado. Si dice 'true' o no existe, está permitido.
    return pwdNode.allowReuse !== false;
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
    Logger.log(`[ID-004] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR EN MEMORIA",
      riesgo004: "",
      score004: "",
      comentario004: msg
    };
  }
}