/**
 * Estrategia para auditar el control de acceso a Google Vault (eDiscovery).
 * Realiza una auditoría de dos capas:
 *   Capa 1: Escanea TODOS los roles (predefinidos y personalizados) para encontrar
 *           aquellos que contengan privilegios específicos de Vault en su arreglo rolePrivileges.
 *   Capa 2: Cruza esos roles con el Censo en RAM para identificar exactamente qué usuarios
 *           tienen capacidad de acceder a Vault.
 *
 * Diferencia con ID-034:
 *   - ID-034 solo verifica si los Super Admins tienen Vault habilitado (check binario).
 *   - ID-042 inventaría TODAS las identidades con privilegios de Vault (cualquier rol).
 */
class VaultAccessControlStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-042", 
        valueKey: "valorPrincipal",
        noteKey: "comentario042",
        riskKey: "riesgo042",
        scoreKey: "score042"
      }
    ];
    super("Vault eDiscovery Access Control Audit", configIDs);
    this.customerId = customerId;
    this.category = "Administración";

    // Privilegios específicos de Google Vault que otorgan acceso a eDiscovery
    this.VAULT_PRIVILEGE_KEYWORDS = [
      "MANAGE_MATTERS",
      "MANAGE_HOLDS",
      "MANAGE_SEARCHES",
      "MANAGE_EXPORTS",
      "MANAGE_AUDIT",
      "ACCESS_ALL_LOGS",
      "VIEW_MATTERS",
      "VAULT"
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

  evaluateInMemory(globalContext) {
    const { census } = globalContext;

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo no encontrado en memoria).");
    }

    Logger.log("========== INICIO DIAGNÓSTICO ID-042 (VAULT eDISCOVERY ACCESS) ==========");

    // =====================================================================
    // CAPA 1: Escanear todos los roles del dominio buscando privilegios de Vault
    // =====================================================================
    const rolesConVault = [];

    try {
      let pageToken = null;
      do {
        const response = AdminDirectory.Roles.list(this.customerId, { 
          maxResults: 100, 
          pageToken: pageToken 
        });
        const roles = response.items || [];

        for (const role of roles) {
          const privileges = role.rolePrivileges || [];
          
          // Buscamos si alguno de los privilegios del rol coincide con los de Vault
          const vaultPrivileges = privileges.filter(p => 
            this.VAULT_PRIVILEGE_KEYWORDS.some(keyword => 
              (p.privilegeName || "").toUpperCase().includes(keyword)
            )
          );

          if (vaultPrivileges.length > 0) {
            rolesConVault.push({
              roleId: role.roleId,
              roleName: role.roleName,
              isSystemRole: role.isSystemRole || false,
              privilegiosVault: vaultPrivileges.map(p => p.privilegeName)
            });
          }
        }
        pageToken = response.nextPageToken;
      } while (pageToken);

    } catch (e) {
      Logger.log(`[ID-042] Error al escanear roles: ${e.message}`);
      return this._buildErrorResponse(`Error al consultar AdminDirectory.Roles.list: ${e.message}`);
    }

    Logger.log(`[ID-042] Roles con privilegios de Vault encontrados: ${rolesConVault.length}`);
    rolesConVault.forEach(r => {
      Logger.log(`  -> ${r.roleName} (${r.isSystemRole ? "Sistema" : "Personalizado"}) | Privilegios: ${r.privilegiosVault.join(", ")}`);
    });

    // =====================================================================
    // CAPA 2: Cruzar con el Censo para mapear usuarios con acceso a Vault
    // =====================================================================
    const vaultRoleIds = new Set(rolesConVault.map(r => r.roleId));
    const vaultRoleNames = rolesConVault.map(r => r.roleName.toLowerCase());
    const usuariosConAcceso = [];

    for (const user of census) {
      if (!user.adminRoles || user.adminRoles.length === 0) continue;

      // Verificamos si alguno de sus roles coincide con los que tienen privilegios de Vault
      const rolesVaultDelUsuario = user.adminRoles.filter(role =>
        vaultRoleIds.has(role.roleId) || 
        vaultRoleNames.some(name => role.roleName.toLowerCase().includes(name))
      );

      if (rolesVaultDelUsuario.length > 0) {
        usuariosConAcceso.push({
          email: user.email || user.id,
          roles: rolesVaultDelUsuario.map(r => `${r.roleName} (${r.scopeType})`).join(", ")
        });
      }
    }

    const totalConAcceso = usuariosConAcceso.length;
    const totalAdmins = census.filter(u => u.isAdmin).length;
    
    Logger.log(`[ID-042] Usuarios con acceso a Vault: ${totalConAcceso}`);
    usuariosConAcceso.forEach(u => {
      Logger.log(`  -> ${u.email} | Roles: ${u.roles}`);
    });

    Logger.log("========== FIN DIAGNÓSTICO ID-042 ==========");

    // =====================================================================
    // LÓGICA DE SALIDA
    // =====================================================================
    let respuestaConcreta;
    let riesgo042, comentario042;

    const porcentajeNum = totalAdmins > 0 ? Math.round((totalConAcceso / totalAdmins) * 100) : 0;
    respuestaConcreta = `${porcentajeNum}%`;

    if (totalConAcceso === 0) {
      riesgo042 = "Bajo";
      comentario042 = `Postura segura. No se detectaron usuarios con roles que otorguen privilegios de acceso a Google Vault (eDiscovery). ${rolesConVault.length} rol(es) con capacidades de Vault fueron escaneados en el dominio, pero ninguno tiene asignaciones activas.`;
    } else if (totalConAcceso <= 2) {
      riesgo042 = "Bajo";
      const detalle = usuariosConAcceso.map(u => `${u.email} [${u.roles}]`).join("; ");
      comentario042 = `${totalConAcceso} de ${totalAdmins} administradores tienen acceso a Google Vault: ${detalle}. El número de cuentas con acceso a eDiscovery es reducido y controlado.`;
    } else {
      riesgo042 = "Medio";
      const detalle = usuariosConAcceso.map(u => `${u.email} [${u.roles}]`).join("; ");
      comentario042 = `ATENCIÓN: ${totalConAcceso} de ${totalAdmins} administradores tienen acceso a Google Vault (eDiscovery): ${detalle}. Se recomienda restringir el acceso a Vault al mínimo de cuentas necesarias para cumplir con el principio de menor privilegio. Los datos de eDiscovery contienen información sensible de retenciones legales y búsquedas forenses.`;
    }

    Logger.log(`[LOG] Vault Access Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo042}`);

    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario042: comentario042,
      riesgo042: riesgo042,
      score042: this.calcularScoreDeRiesgo(riesgo042)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-042] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo042: "Medio",
      score042: 2,
      comentario042: msg
    };
  }
}