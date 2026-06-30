/**
 * Estrategia para auditar a los usuarios con el rol de Administrador de Gestión de Usuarios
 * delegado específicamente por Unidad Organizativa (ORG_UNIT).
 * Utiliza el Censo en RAM (O(1)) para evitar llamadas redundantes.
 * Contiene la lógica de negocio para ID-036.
 */
class UserManagementAdminRoleStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    const configIDs = [
      { 
        id: "ID-036", 
        valueKey: "valorPrincipal",
        noteKey: "comentario036",
        riskKey: "riesgo036",
        scoreKey: "score036"
      }
    ];

    super("User Management Admin Role Assignments Audit (By OU)", configIDs);
    this.roleId = roleId; // Guardamos para la validación en memoria
    this.category = "Administración";
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

    const totalAdmins = census.filter(u => u.isAdmin).length;
    
    if (totalAdmins === 0) {
      return this._buildErrorResponse("El censo no contiene usuarios administradores para auditar.");
    }

    // 1. FILTRAR USUARIOS CON EL ROL ESPECÍFICO DELEGADO POR OU
    const adminsList = [];
    const delegationDetails = [];
    // NUEVO: También detectamos admins con el mismo rol a nivel global (CUSTOMER)
    const globalAdminsList = [];
    
    for (const user of census) {
      if (!user.isAdmin || !user.adminRoles || user.adminRoles.length === 0) continue;

      // Criterio primario: roleId numérico real (resuelto dinámicamente por AuthService)
      // Criterio secundario (fallback): coincidencia por nombre del sistema
      const matchingRoles = user.adminRoles.filter(role => 
        role.roleId === this.roleId || role.roleName.toLowerCase().includes("user management admin")
      );

      // Separar por scope: delegaciones por OU vs globales
      const ouDelegations = matchingRoles.filter(role => role.scopeType === "ORG_UNIT");
      const globalDelegations = matchingRoles.filter(role => role.scopeType === "CUSTOMER");
      
      if (ouDelegations.length > 0) {
        adminsList.push(user.email || user.id);
        ouDelegations.forEach(del => {
          delegationDetails.push(`${user.email} (OU Delegada: ${del.orgUnitId})`);
        });
      }

      if (globalDelegations.length > 0) {
        globalAdminsList.push(user.email || user.id);
      }
    }
    
    const adminCount = adminsList.length;    
    const porcentajeNum = Math.round((adminCount / totalAdmins) * 100);

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo036, comentario036;

    respuestaConcreta = `${porcentajeNum}%`;

    if (adminCount > 0) {
      // Delegar por OU es una buena práctica (Principio de menor privilegio), pero aún así debe ser auditado
      riesgo036 = "Bajo"; 
      comentario036 = `Buenas prácticas: ${adminCount} de ${totalAdmins} administradores tienen el rol de Gestión de Usuarios delegado correctamente de forma granular (por Unidad Organizativa). Esto limita su alcance y evita que tengan acceso sobre toda la empresa.`;
    } else if (globalAdminsList.length > 0) {
      // No hay delegación por OU, pero SÍ hay admins globales con este rol → Riesgo real
      riesgo036 = "Medio";
      comentario036 = `Atención: ${globalAdminsList.length} administrador(es) tienen el rol de Gestión de Usuarios a nivel GLOBAL (${globalAdminsList.join(", ")}), pero ninguno está delegado por Unidad Organizativa. Se recomienda migrar a un modelo de administración delegada por OU para cumplir con el principio de menor privilegio.`;
    } else {
      // Nadie tiene el rol en ninguna modalidad
      riesgo036 = "Bajo";
      comentario036 = `No se encontraron administradores con el rol de Gestión de Usuarios, ni a nivel global ni por Unidad Organizativa.`;
    }

    // Trazabilidad técnica para la consola
    Logger.log(`[LOG] User Management Admin Audit (In-Memory): Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo036}`);
    if (adminCount > 0) {
      Logger.log(`[ID-036] Administradores delegados por OU:\n${delegationDetails.join("\n")}`);
    }
    if (globalAdminsList.length > 0) {
      Logger.log(`[ID-036] Administradores con rol global (CUSTOMER): ${globalAdminsList.join(", ")}`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO
    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario036: comentario036,
      riesgo036: riesgo036,
      score036: this.calcularScoreDeRiesgo(riesgo036)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-036] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR_MEMORIA",
      riesgo036: "Medio",
      score036: 2,
      comentario036: msg
    };
  }
}