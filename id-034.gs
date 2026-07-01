/**
 * Estrategia para auditar si los Súper Administradores tienen acceso efectivo a Google Vault.
 * 
 * ══════════════════════════════════════════════════════════════════════════
 * ARQUITECTURA DE EVALUACIÓN MULTICAPA
 * ══════════════════════════════════════════════════════════════════════════
 * 
 * Esta estrategia combina dos barreras de control:
 *   1. Estado del Servicio (Policy API en RAM): Verifica si Google Vault está 
 *      explícitamente deshabilitado para la OU Raíz.
 *   2. Licenciamiento (Censo en RAM): Verifica si los Súper Admins poseen un SKU 
 *      que incluya Vault.
 * 
 * La Policy API omite la política cuando Vault usa su estado por defecto 
 * (habilitado para todos). Si no se encuentra 'vault.service_status', se 
 * asume Habilitado (Por defecto).
 * 
 * Contiene la lógica de negocio para ID-034.
 */
class VaultSuperAdminLicenseAuditStrategy extends ApiStrategy {
  constructor(customerId, superAdminRoleId) {
    const configIDs = [
      { 
        id: "ID-034", 
        valueKey: "valorPrincipal",
        noteKey: "comentario034",
        riskKey: "riesgo034",
        scoreKey: "score034"
      }
    ];
    super("Google Vault Super Admin Access Audit", configIDs);
    this.customerId = customerId;
    this.superAdminRoleId = superAdminRoleId;
    this.category = "Administración";

    this.VAULT_RISK_SKUS = [
      "/product/Google-Apps/sku/1010020020",  // Google Workspace Enterprise Standard
      "/product/Google-Apps/sku/1010020025",  // Google Workspace Enterprise Plus
      "/product/Google-Apps/sku/1010020027",  // Google Workspace Business Plus
      "/product/Google-Apps/sku/1010020030",  // Google Workspace Enterprise Starter
      "/product/Google-Apps/sku/1010020029",  // Google Workspace Education Plus
      "/product/Google-Apps/sku/1010020026",  // Google Workspace Education Standard
      "/product/Google-Apps/sku/1010340002",  // Google Vault (Add-on independiente)
      "/product/Google-Apps/sku/1010340001"   // Google Vault - Former (legacy)
    ];
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  _verificarLicenciaVaultAdmin(userObj) {
    try {
      const userLicenses = userObj.licenses || [];
      if (userLicenses.length === 0) return { tieneVault: false, skusConVault: [] };
      const skusConVault = userLicenses.filter(sku => this.VAULT_RISK_SKUS.includes(sku));
      return { tieneVault: skusConVault.length > 0, skusConVault: skusConVault };
    } catch (e) {
      return { tieneVault: false, skusConVault: [] };
    }
  }

  evaluateInMemory(globalContext) {
    const { census, policies } = globalContext;

    if (!census || !policies) {
      return this._buildErrorResponse("Falta el contexto global (censo o políticas no encontradas en memoria).");
    }

    Logger.log("========== INICIO DIAGNÓSTICO ID-034 (VAULT: SERVICIO + LICENCIAS) ==========");

    // =====================================================================
    // PASO 1: Identificar Súper Admins globales desde el censo en RAM
    // =====================================================================
    const superAdminsList = [];

    for (const user of census) {
      let isSuperAdmin = user.isAdmin === true;
      if (!isSuperAdmin && user.adminRoles && user.adminRoles.length > 0) {
        isSuperAdmin = user.adminRoles.some(role => 
          (role.roleId === this.superAdminRoleId || role.roleName.toLowerCase().includes("super admin"))
          && role.scopeType === "CUSTOMER"
        );
      }
      if (isSuperAdmin) {
        superAdminsList.push(user);
      }
    }

    const superAdminCount = superAdminsList.length;
    Logger.log(`[ID-034] Súper Admins globales detectados: ${superAdminCount}`);

    // =====================================================================
    // PASO 2: Evaluar el estado del servicio de Vault desde policies en RAM
    // =====================================================================
    let vaultStatus = "Habilitado (Por defecto)";
    let vaultExplicitlyDisabled = false;

    try {
      const vaultPolicies = policies.filter(p => p.setting && p.setting.type === "vault.service_status");
      
      if (vaultPolicies.length > 0) {
        // Encontrar la política aplicable a la OU Raíz
        const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(vaultPolicies, "vault.service_status") || vaultPolicies[0];
        
        if (rootPolicy && rootPolicy.setting) {
          const nodeStr = JSON.stringify(rootPolicy.setting).toUpperCase();
          const isEnabled = nodeStr.includes('"STATE":"ENABLED"') || 
                            nodeStr.includes('"SERVICESTATE":"ENABLED"') ||
                            nodeStr.includes('"ENABLED":TRUE');

          if (isEnabled) {
            vaultStatus = "Habilitado (Explícito)";
          } else {
            vaultStatus = "Deshabilitado (Explícito)";
            vaultExplicitlyDisabled = true;
          }
        }
      }
    } catch (e) {
      Logger.log(`[ID-034] Error al evaluar estado de Vault en memoria: ${e.message}`);
      vaultStatus = "Habilitado (Por defecto - Error en lectura)";
    }

    Logger.log(`[ID-034] Estado del servicio Vault en la raíz: ${vaultStatus}`);

    // =====================================================================
    // PASO 3: Evaluar licencias y emitir diagnóstico final
    // =====================================================================
    let respuestaConcreta;
    let riesgo034, comentario034;

    if (superAdminCount === 0) {
      respuestaConcreta = "NOT_APPLICABLE";
      riesgo034 = "Bajo";
      comentario034 = "No se detectaron cuentas con el rol de Súper Administrador global en el dominio. El control no es aplicable.";
    } else if (vaultExplicitlyDisabled) {
      respuestaConcreta = "COMPLIANT (Servicio Apagado)";
      riesgo034 = "Bajo";
      comentario034 = `Postura segura. El servicio de Google Vault está explícitamente deshabilitado a nivel global. Los ${superAdminCount} Súper Administrador(es) del dominio no pueden acceder a eDiscovery independientemente de sus licencias.`;
    } else {
      // Si el servicio está habilitado (por defecto o explícito), dependemos de las licencias
      const adminsConVault = [];
      const adminsSinVault = [];

      for (const admin of superAdminsList) {
        const resultado = this._verificarLicenciaVaultAdmin(admin);
        if (resultado.tieneVault) adminsConVault.push(admin.email);
        else adminsSinVault.push(admin.email);
      }

      if (adminsConVault.length > 0) {
        respuestaConcreta = `NON_COMPLIANT (${vaultStatus})`;
        riesgo034 = "Alto";
        comentario034 = `ALERTA: Google Vault se encuentra ${vaultStatus.toLowerCase()} y ${adminsConVault.length} Súper Administrador(es) poseen una licencia activa de Vault (${adminsConVault.join(", ")}). Esto les otorga acceso irrevocable a eDiscovery. Se recomienda deshabilitar el servicio de Vault para Súper Admins o retirarles la licencia.`;
      } else {
        respuestaConcreta = `COMPLIANT (Sin Licencia)`;
        riesgo034 = "Bajo";
        comentario034 = `Postura segura mitigada. Aunque Vault está ${vaultStatus.toLowerCase()}, los ${superAdminCount} Súper Administrador(es) del dominio no poseen licencias que incluyan Vault. Sin licencia activa, la plataforma bloquea su acceso.`;
      }
    }

    Logger.log(`[ID-034] Diagnóstico final: ${respuestaConcreta} | Riesgo: ${riesgo034}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-034 ==========");

    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario034: comentario034,
      riesgo034: riesgo034,
      score034: this.calcularScoreDeRiesgo(riesgo034)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-034] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR_MEMORIA",
      riesgo034: "Medio",
      score034: 2,
      comentario034: msg
    };
  }
}
