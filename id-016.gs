/**
 * Estrategia de Recuperación de Cuenta para Superadministradores (En Memoria).
 * Propósito: Auditar si las cuentas con privilegios máximos pueden recuperar su 
 * contraseña por autoservicio (Ej. SMS), lo cual representa un riesgo crítico.
 * https://docs.cloud.google.com/identity/docs/concepts/policy-api-concepts#reducers_for_settings
 * Referencia: security.super_admin_account_recovery
 */
class SuperAdminAccountRecoveryPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-016", 
        valueKey: "valorPrincipal",
        noteKey: "comentario016",
        riskKey: "riesgo016",
        scoreKey: "score016"
      }
    ];

    super("Super Admin Account Recovery Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { census, policies } = globalContext;

    if (!census || !policies) {
      return this._buildErrorResponse("Falta el contexto global (censo o políticas).");
    }

    // =======================================================================
    // PASO 1: FILTRAR POLÍTICAS DE RECUPERACIÓN PARA SUPER ADMINS
    // =======================================================================
    const saRecoveryPolicies = policies.filter(p => p.setting && p.setting.type.includes("security.super_admin_account_recovery"));
    Logger.log(`[ID-016] Políticas de Recuperación de Super Admin encontradas: ${saRecoveryPolicies.length}`);

    // =======================================================================
    // PASO 2: ESCENARIO A - SILENCIO DE LA API (APLICA VALOR POR DEFECTO)
    // Según la documentación, si no hay política, el default es FALSE (Seguro)
    // =======================================================================
    if (saRecoveryPolicies.length === 0) {
      Logger.log("[DEBUG ID-016] La API omitió datos. Asumiendo valor seguro por defecto (Deshabilitado).");
      return {
        name: this.name,
        valorPrincipal: "Deshabilitado (0%)",
        comentario016: "Práctica Segura (Fábrica): La API no reporta políticas anómalas. El 0% de los administradores tiene habilitada la recuperación por autoservicio.",
        riesgo016: "Bajo",
        score016: this.calcularScoreDeRiesgo("Bajo")
      };
    }

    // =======================================================================
    // PASO 3: ESCENARIO B - EVALUAR POLÍTICA RAÍZ
    // =======================================================================
    const rootPolicy = saRecoveryPolicies.find(p => !(p.query || "").includes("entity."));
    
    let isRootRecoveryEnabled = false; 
    
    if (rootPolicy && rootPolicy.setting) {
      isRootRecoveryEnabled = this._isRecoveryEnabled(rootPolicy);
    }

    const estadoPrincipal = isRootRecoveryEnabled ? "Habilitado" : "Deshabilitado";
    Logger.log(`[ID-016] Raíz de la Org: Recuperación de Súper Admins = ${estadoPrincipal}`);

    // =======================================================================
    // PASO 4: AISLAR ESTRICTAMENTE A LOS SUPER ADMINISTRADORES
    // =======================================================================
    const administradores = census.filter(user => user.isAdmin === true);
    const totalAdmins = administradores.length;

    if (totalAdmins === 0) {
      Logger.log("[ID-016] AVISO: No se encontraron Administradores en el censo para auditar.");
      return {
        name: this.name,
        valorPrincipal: "N/A",
        comentario016: "No se detectaron cuentas de administrador en el censo.",
        riesgo016: "Medio",
        score016: this.calcularScoreDeRiesgo("Medio")
      };
    }

    // =======================================================================
    // PASO 5: CALCULAR VULNERABILIDAD FORENSE
    // =======================================================================
    let adminsVulnerables = 0;
    
    for (const admin of administradores) {
      const aplicables = saRecoveryPolicies.filter(p => CELParserEngine.evaluate(p, admin));
      const politicaGanadora = PolicyReducerFactory.reduce(aplicables, "security.super_admin_account_recovery");

      if (this._isRecoveryEnabled(politicaGanadora)) {
        adminsVulnerables++;
      }
    }

    const porcentajeVulnerables = Math.round((adminsVulnerables / totalAdmins) * 100);

    // =======================================================================
    // PASO 6: ASIGNACIÓN DE RIESGOS
    // =======================================================================
    let riesgo016, comentario016, valorPrincipalFormateado;
    if (porcentajeVulnerables === 0) {
       riesgo016 = "Bajo";
       comentario016 = `Seguro: El 0% de los administradores tiene habilitada la recuperación de cuenta por autoservicio. Esto previene secuestros de cuentas maestras.`;
       valorPrincipalFormateado = "Deshabilitado (0%)";
    } else {
       riesgo016 = "Alto";
       comentario016 = `Riesgo Crítico: El ${porcentajeVulnerables}% de los administradores (${adminsVulnerables}/${totalAdmins}) puede recuperar su contraseña por autoservicio. Si un atacante vulnera un correo secundario o teléfono personal, tomará control del dominio.`;
       valorPrincipalFormateado = `Habilitado (${porcentajeVulnerables}%)`;
    }

    Logger.log(`[ID-016] Métrica procesada. Riesgo: ${riesgo016}. Admins con recuperación vulnerable: ${porcentajeVulnerables}%`);

    return {
      name: this.name,
      valorPrincipal: valorPrincipalFormateado, 
      comentario016: comentario016,
      riesgo016: riesgo016,
      score016: this.calcularScoreDeRiesgo(riesgo016)
    };
  }

  _isRecoveryEnabled(policy) {
    if (!policy || !policy.setting) return false;
    const configNode = policy.setting.value || policy.setting;
    const recoveryNode = configNode.superAdminAccountRecovery || configNode;
    return recoveryNode.enableAccountRecovery === true || recoveryNode.enable_account_recovery === true;
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return "";
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-016] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR EN MEMORIA",
      riesgo016: "",
      score016: "",
      comentario016: msg
    };
  }
}