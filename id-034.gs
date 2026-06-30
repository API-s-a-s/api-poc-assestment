/**
 * Estrategia para auditar si los Súper Administradores tienen acceso efectivo a Google Vault.
 * 
 * Esta estrategia ABANDONA la consulta a la Policy API de Cloud Identity
 * (vault.service_status) porque:
 * 
 *   1. La OU raíz siempre devuelve ENABLED por defecto (falso positivo).
 *   2. Los Súper Admins eluden restricciones de servicio por OU.
 *   3. Un Súper Admin puede autoasignarse privilegios de Vault en cualquier momento.
 * 
 * En su lugar, implementa una auditoría multicapa basada en LICENCIAS:
 * 
 *   Paso 1 (Directorio): Identifica Súper Admins globales desde el censo en RAM.
 *   Paso 2 (Licencias):  Para cada Súper Admin, evalúa si posee un SKU que
 *                         incluya Google Vault (Enterprise, Business Plus, Add-ons).
 *   Paso 3 (Evaluación): Emite el diagnóstico final basado en licencias activas.
 * 
 * A partir de noviembre de 2025, la ÚNICA barrera técnica real que impide a un
 * Súper Administrador interactuar con eDiscovery es la ausencia de una licencia
 * activa que incluya Google Vault.
 * 
 * Fuentes de datos:
 *   - Censo en RAM O(1): 00-core-censo.gs (usuarios, roles, licencias)
 *   - NO realiza llamadas adicionales a ninguna API.
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
    super("Google Vault Super Admin License Audit", configIDs);
    this.customerId = customerId;
    this.superAdminRoleId = superAdminRoleId;
    this.category = "Administración";

    /**
     * SKUs de riesgo: licencias que incluyen acceso a Google Vault.
     * Formato del censo: "/product/Google-Apps/sku/{skuId}"
     * Ref: https://developers.google.com/admin-sdk/licensing/v1/how-tos/products
     */
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

  // Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return null;
  }

  /**
   * Función helper: Verifica si un usuario del censo tiene al menos un SKU
   * que incluya acceso a Google Vault.
   * 
   * @param {Object} userObj - Objeto del censo con la propiedad `licenses` (array de strings).
   * @return {{ tieneVault: boolean, skusConVault: string[] }} Resultado de la verificación.
   */
  _verificarLicenciaVaultAdmin(userObj) {
    try {
      const userLicenses = userObj.licenses || [];

      if (userLicenses.length === 0) {
        Logger.log(`[ID-034] ${userObj.email}: Sin licencias asignadas → Sin acceso a Vault.`);
        return { tieneVault: false, skusConVault: [] };
      }

      // Intersección: licencias del usuario ∩ SKUs de riesgo
      const skusConVault = userLicenses.filter(sku => this.VAULT_RISK_SKUS.includes(sku));

      if (skusConVault.length > 0) {
        Logger.log(`[ID-034] ${userObj.email}: POSEE licencia(s) con Vault → ${skusConVault.join(", ")}`);
      } else {
        Logger.log(`[ID-034] ${userObj.email}: Licencias activas sin Vault (${userLicenses.length} SKU(s) asignados).`);
      }

      return { tieneVault: skusConVault.length > 0, skusConVault: skusConVault };
    } catch (e) {
      Logger.log(`[ID-034] ERROR al verificar licencias de ${userObj.email || "desconocido"}: ${e.message}`);
      return { tieneVault: false, skusConVault: [] };
    }
  }

  evaluateInMemory(globalContext) {
    const { census } = globalContext;

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo no encontrado en memoria).");
    }

    Logger.log("========== INICIO DIAGNÓSTICO ID-034 (VAULT + LICENCIAS SUPER ADMINS) ==========");

    // =====================================================================
    // PASO 1: Identificar Súper Admins globales desde el censo en RAM
    // Un Súper Admin se identifica por:
    //   - user.isAdmin === true
    //   - Al menos un rol con roleName que incluya "super admin" Y
    //     scopeType === "CUSTOMER" (alcance global, no por OU)
    // =====================================================================
    const superAdminsList = [];

    for (const user of census) {
      // Un usuario es Súper Admin si tiene el flag nativo isAdmin = true 
      // O si tiene el rol asignado explícitamente en su array de adminRoles
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

    if (superAdminCount > 0) {
      Logger.log(`[ID-034] Cuentas Súper Admin: ${superAdminsList.map(u => u.email).join(", ")}`);
    }

    // =====================================================================
    // PASO 2: Evaluar licencias con Vault para cada Súper Admin
    // Se reutiliza el array user.licenses del censo (poblado por
    // CensusStateWrapper._buildLicensesHashMap en 00-core-censo.gs).
    // NO se realizan llamadas adicionales a la API.
    // =====================================================================
    const adminsConVault = [];   // Súper Admins CON licencia que incluye Vault
    const adminsSinVault = [];   // Súper Admins SIN licencia que incluye Vault
    const details = [];          // Array de strings para trazabilidad

    for (const admin of superAdminsList) {
      const resultado = this._verificarLicenciaVaultAdmin(admin);

      if (resultado.tieneVault) {
        adminsConVault.push(admin.email);
        details.push(`⚠ ${admin.email} → Tiene acceso a Vault (SKU: ${resultado.skusConVault.join(", ")})`);
      } else {
        adminsSinVault.push(admin.email);
        details.push(`✓ ${admin.email} → Sin licencia de Vault (mitigado)`);
      }
    }

    Logger.log(`[ID-034] Resultado de licencias: ${adminsConVault.length} con Vault, ${adminsSinVault.length} sin Vault.`);

    // =====================================================================
    // PASO 3: Diagnóstico final basado en licencias
    //
    //   - Si hay Súper Admins con licencias activas de Vault → NON_COMPLIANT (Alto)
    //   - Si hay Súper Admins pero ninguno tiene licencia con Vault → COMPLIANT (Bajo)
    //   - Si no hay Súper Admins detectados → NOT_APPLICABLE
    // =====================================================================
    let respuestaConcreta;
    let riesgo034, comentario034;

    if (superAdminCount === 0) {
      // Caso defensivo: No se detectaron Súper Admins
      respuestaConcreta = "NOT_APPLICABLE";
      riesgo034 = "Bajo";
      comentario034 = "No se detectaron cuentas con el rol de Súper Administrador global en el dominio. El control no es aplicable.";
      details.push("ℹ Sin Súper Administradores en el dominio.");
    } else if (adminsConVault.length > 0) {
      // NON_COMPLIANT: Existen Súper Admins con acceso efectivo irrevocable a Vault
      respuestaConcreta = "Habilitado";
      riesgo034 = "Alto";
      comentario034 = `${adminsConVault.length} de ${superAdminCount} cuentas de súper administrador poseen una licencia activa que incluye Google Vault (${adminsConVault.join(", ")}). Esto les otorga acceso efectivo e irrevocable a eDiscovery y búsquedas  de todo el dominio.`;
    } else {
      // COMPLIANT: Hay Súper Admins pero ninguno tiene licencia con Vault
      respuestaConcreta = "Deshabilitado";
      riesgo034 = "Bajo";
      comentario034 = `Los ${superAdminCount} Súper Administradores del dominio no poseen licencias que incluyan Google Vault (${adminsSinVault.join(", ")}). Sin una licencia activa con Vault, la plataforma de eDiscovery bloquea su acceso independientemente de sus roles administrativos.`;
    }

    Logger.log(`[ID-034] Diagnóstico final: ${respuestaConcreta} | Riesgo: ${riesgo034}`);
    Logger.log(`[ID-034] Detalles: ${JSON.stringify(details)}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-034 ==========");

    // 4. RETORNAR EL OBJETO CONSOLIDADO
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
