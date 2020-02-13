using System.Linq;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebAppWithEFCore.Pages
{
    public class IndexModel : PageModel
    {
        public string Firstname { get; set; }
        public string Lastname { get; set; }

        private readonly WebAppDbContext _dbContext;

        public IndexModel(WebAppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public void OnGet()
        {
            var user = _dbContext.AkvTestTable.Single();

            Firstname = user.FirstName;
            Lastname = user.LastName;
        }
    }
}
