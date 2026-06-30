/**
 * Estrategia para auditar Dispositivos de Confianza en MFA (En Memoria).
 * Propósito: Auditar si la organización permite a los usuarios marcar equipos 
 * como "de confianza" para saltarse el segundo factor de autenticación.
 * Referencia: https://docs.cloud.google.com/identity/docs/concepts/policy-api-concepts#reducers_for_settings
 */
class TrustedDevice2SVPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-011", 
        valueKey: "valorPrincipal",
        noteKey: "comentario011",
        riskKey: "riesgo011",
        scoreKey: "score011"
      }
    ];

    super("Trusted Devices for 2SV Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { census, policies } = globalContext;

    if (!census || !policies) {
      return this._buildErrorResponse("Falta el contexto global (censo o políticas).");
    }
    
    // =======================================================================
    // PASO 1: FILTRAR POLÍTICAS DE DISPOSITIVOS DE CONFIANZA
    // Usamos el endpoint correcto mencionado en la documentación
    // =======================================================================
    const trustPolicies = policies.filter(p => p.setting && p.setting.type.includes("security.two_step_verification_device_trust"));
    Logger.log(`[ID-011] Políticas de Dispositivos de Confianza encontradas en memoria: ${trustPolicies.length}`);
    Logger.log(`[ID-011] JSON de políticas obtenidas: ${JSON.stringify(trustPolicies, null, 2)}`);

    // =======================================================================
    // PASO 2: ESCENARIO A - SILENCIO DE LA API
    // Si la API no envía datos, asumimos estado "empty." estándar de la matriz.
    // =======================================================================
    if (trustPolicies.length === 0) {
      Logger.log("[DEBUG ID-011] AVISO: La API no retorna datos para Dispositivos de Confianza. Se asume el comportamiento por defecto (Permitido).");
    }

    // =======================================================================
    // PASO 3: ESCENARIO B - EVALUAR POLÍTICA RAÍZ
    // Buscamos la regla general que aplica a todo el dominio (sin 'entity.')
    // =======================================================================
    const rootPolicy = trustPolicies.find(p => !(p.query || "").includes("entity."));
    
    // Por defecto de fábrica, Google permite los dispositivos de confianza
    let isRootTrustAllowed = true; 
    
    if (rootPolicy && rootPolicy.setting) {
      isRootTrustAllowed = this._isTrustAllowed(rootPolicy);
    }

    const estadoPrincipal = isRootTrustAllowed ? "Habilitado" : "Deshabilitado";
    Logger.log(`[ID-011] Raíz de la Org: Dispositivos de confianza = ${estadoPrincipal}`);

    // =======================================================================
    // PASO 4: CALCULAR PORCENTAJE DE USUARIOS PERMITIDOS (CENSO)
    // Usamos el motor CEL para cruzar las políticas contra la topología
    // =======================================================================
    let usuariosPermitidos = 0;
    let usuariosBloqueados = 0;
    
    for (const user of census) {
      const aplicables = trustPolicies.filter(p => CELParserEngine.evaluate(p, user));
      
      // El motor usará _maxReducer (vía default) para decidir la regla ganadora
      const politicaGanadora = PolicyReducerFactory.reduce(aplicables, "security.two_step_verification_device_trust");

      if (this._isTrustAllowed(politicaGanadora)) {
        usuariosPermitidos++;
      } else {
        usuariosBloqueados++;
      }
    }

    const totalUsuarios = usuariosPermitidos + usuariosBloqueados;
    // Calculamos el % de usuarios que TIENEN PERMITIDO confiar en el dispositivo
    const porcentajePermitidos = totalUsuarios > 0 ? Math.round((usuariosPermitidos / totalUsuarios) * 100) : 0;
    
    // =======================================================================
    // PASO 5: ASIGNAR RIESGO Y CONSTRUIR RESULTADO
    // Permitir dispositivos de confianza es un riesgo (Medio según el script original). 
    // Bloquearlo es un nivel de seguridad más estricto (Riesgo Bajo).
    // =======================================================================
    let respuestaConcreta;
    let riesgo011, comentario011;

    if (porcentajePermitidos === 0) {
      respuestaConcreta = `Bloqueado (0%)`;
      riesgo011 = "Bajo";
      comentario011 = `El 0% de los usuarios puede marcar dispositivos como confiables.`;
    } else {
      respuestaConcreta = `Permitido (${porcentajePermitidos}%)`;
      riesgo011 = "Medio";
      comentario011 = `El ${porcentajePermitidos}% de los usuarios puede marcar dispositivos como confiables.`;
    }
    
    Logger.log(`[ID-011] Métrica procesada. Riesgo: ${riesgo011}. Permitido para: ${porcentajePermitidos}% de usuarios.`);

    return {
      name: this.name,
      valorPrincipal: respuestaConcreta, 
      comentario011: comentario011,
      riesgo011: riesgo011,
      score011: this.calcularScoreDeRiesgo(riesgo011)
    };
  }

  // =======================================================================
  // HELPER: Valida la configuración de la política ganadora
  // =======================================================================
  _isTrustAllowed(policy) {
    if (!policy || !policy.setting) return true; // Asumimos permitido si no hay regla estricta

    const configNode = policy.setting.value || policy.setting;
    const trustNode = configNode.twoStepVerificationDeviceTrust || configNode;
    
    // Validamos que exista explícitamente y verificamos si está apagado (false)
    // Usamos ambos formatos posibles (snake_case y camelCase) por seguridad
    const isExplicitlyFalse = trustNode.allow_trusting_device === false || trustNode.allowTrustingDevice === false;

    // Si es explícitamente falso, está bloqueado. Si no, está permitido.
    return !isExplicitlyFalse;
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
    Logger.log(`[ID-011] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR EN MEMORIA",
      riesgo011: "",
      score011: "",
      comentario011: msg
    };
  }
}