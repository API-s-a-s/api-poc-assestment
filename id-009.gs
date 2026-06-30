/**
 * Estrategia de Exigencia de Verificación en 2 Pasos (2SV Enforcement) para Usuarios Regulares.
 * Propósito: Auditar si la organización OBLIGA a los usuarios (excluyendo Administradores) a utilizar MFA.
 * Referencia: https://cloud.google.com/identity/docs/concepts/supported-policy-api-settings
 */
class TwoStepVerificationEnforcementPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-009", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario009", 
        riskKey: "riesgo009", 
        scoreKey: "score009" 
      }
    ];
    
    super("2-Step Verification Enforcement Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { census, policies } = globalContext;

    if (!census || !policies) {
      return this._buildErrorResponse("Falta el contexto global (censo o políticas).");
    }
    
    // =======================================================================
    // PASO 1: FILTRAR POLÍTICAS DE EXIGENCIA MFA
    // Buscamos usando .includes() para ignorar el prefijo 'settings/'
    // =======================================================================
    const enforcementPolicies = policies.filter(p => p.setting && p.setting.type.includes("security.two_step_verification_enforcement"));
    Logger.log(`[ID-009] Políticas de exigencia MFA encontradas en memoria: ${enforcementPolicies.length}`);

    // =======================================================================
    // PASO 2: ESCENARIO A - SILENCIO DE LA API
    // Por defecto de fábrica, Google NO obliga a usar 2SV (es opcional).
    // Si la API no envía datos, asumimos este estado predeterminado.
    // =======================================================================
    if (enforcementPolicies.length === 0) {
      Logger.log("[DEBUG ID-009] AVISO: La API no retorna datos para exigencia de 2SV. Se evaluará adopción real (isEnrolledIn2Sv).");
    }

    // =======================================================================
    // PASO 3: ESCENARIO B - EVALUAR POLÍTICA RAÍZ
    // Buscamos la regla general que aplica a todo el dominio (sin 'entity.')
    // =======================================================================
    const rootPolicy = enforcementPolicies.find(p => !(p.query || "").includes("entity."));
    
    let isRootEnforced = false; // Por defecto es opcional
    
    if (rootPolicy && rootPolicy.setting) {
      isRootEnforced = this._isEnforced(rootPolicy);
    }

    const estadoPrincipal = isRootEnforced ? "Obligatorio" : "Opcional";
    Logger.log(`[ID-009] Raíz de la Org: Exigencia de 2SV = ${estadoPrincipal}`);

    // =======================================================================
    // PASO 4: AISLAR A LOS USUARIOS REGULARES DEL CENSO
    // Filtramos excluyendo explícitamente a los administradores.
    // =======================================================================
    const usuariosRegulares = census.filter(user => user.isAdmin !== true);
    const totalRegulares = usuariosRegulares.length;

    if (totalRegulares === 0) {
      Logger.log("[ID-009] AVISO: No se encontraron usuarios regulares en el censo (¿Todos son Admins?).");
      return {
        name: this.name,
        valorPrincipal: "N/A",
        comentario009: "No se detectaron cuentas de usuarios regulares para evaluar.",
        riesgo009: "",
        score009: ""
      };
    }

    Logger.log(`[ID-009] Evaluando la exigencia de 2SV para ${totalRegulares} Usuario(s) Regular(es).`);

    // =======================================================================
    // PASO 5: CALCULAR PORCENTAJE DE OBLIGATORIEDAD Y PROTECCIÓN REAL
    // Usamos el motor CEL para cruzar las políticas contra los usuarios
    // =======================================================================
    let usuariosProtegidos = 0;
    
    for (const user of usuariosRegulares) {
      const aplicables = enforcementPolicies.filter(p => CELParserEngine.evaluate(p, user));
      
      // El motor usará el _maxReducer para decidir qué regla prevalece si hay conflicto
      const politicaGanadora = PolicyReducerFactory.reduce(aplicables, "security.two_step_verification_enforcement");

      const hasEnforcement = this._isEnforced(politicaGanadora);
      const isEnrolled = user.isEnrolledIn2Sv === true;

      if (hasEnforcement || isEnrolled) {
        usuariosProtegidos++;
      }
    }

    // Calculamos el % de USUARIOS REGULARES protegidos
    const porcentajeObligados = Math.round((usuariosProtegidos / totalRegulares) * 100);
    
    // =======================================================================
    // PASO 6: ASIGNAR RIESGO Y CONSTRUIR RESULTADO
    // =======================================================================
    let riesgo009, comentario009;
    let respuestaConcreta;

    if (porcentajeObligados === 100) {
       respuestaConcreta = `Protegido (${porcentajeObligados}%)`;
       riesgo009 = "Bajo";
       comentario009 = `Cumplimiento total. El 100% de los usuarios regulares (${usuariosProtegidos}/${totalRegulares}) están obligados a utilizar o han activado proactivamente la verificación en dos pasos (MFA).`;
    } else if (porcentajeObligados === 0) {
       respuestaConcreta = enforcementPolicies.length === 0 ? "Alerta API (Vacío)" : `Vulnerable (${porcentajeObligados}%)`;
       riesgo009 = "Alto";
       comentario009 = enforcementPolicies.length === 0
         ? `La API no devolvió políticas de enforcement. Ningún usuario regular (0/${totalRegulares}) está obligado ni tiene activa la verificación en dos pasos.`
         : `Riesgo Crítico: Ningún usuario regular (0/${totalRegulares}) está protegido por exigencia o adopción proactiva de MFA.`;
    } else {
       respuestaConcreta = `Parcial (${porcentajeObligados}%)`;
       riesgo009 = "Alto";
       comentario009 = `Vulnerabilidad de Brecha: Adopción fragmentada. Solo el ${porcentajeObligados}% de los usuarios regulares (${usuariosProtegidos}/${totalRegulares}) cuenta con exigencia o adopción activa de MFA.`;
    }
    
    Logger.log(`[ID-009] Métrica procesada. Riesgo: ${riesgo009}. Protegidos: ${porcentajeObligados}% de usuarios regulares.`);

    return {
      name: this.name,
      valorPrincipal: respuestaConcreta, 
      comentario009: comentario009,
      riesgo009: riesgo009,
      score009: this.calcularScoreDeRiesgo(riesgo009)
    };
  }

  // =======================================================================
  // HELPER: Lógica de validación de fechas de Google
  // Verifica si la fecha de obligación es hoy o si está en el pasado.
  // =======================================================================
  _isEnforced(policy) {
    if (!policy || !policy.setting) return false;

    const configNode = policy.setting.value || policy.setting;
    const enforcementNode = configNode.twoStepVerificationEnforcement || configNode;
    
    // Google puede enviar la variable en diferentes formatos según la versión de la API
    const enforcedFrom = enforcementNode.enforcedFrom || enforcementNode.enforced_from;

    if (enforcedFrom) {
      const enforcementDate = new Date(enforcedFrom);
      const today = new Date();
      // Solo es obligatorio si la fecha límite ya se cumplió o es hoy
      return enforcementDate <= today;
    }
    
    return false;
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
    Logger.log(`[ID-009] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR EN MEMORIA",
      riesgo009: "",
      score009: "",
      comentario009: msg
    };
  }
}